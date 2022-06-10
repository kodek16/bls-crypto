package main

import (
	"fmt"
  "flag"
  "os"
	"crypto/rand"
  "encoding/json"
  "encoding/hex"
	"math/big"

	"github.com/eywa-protocol/bls-crypto/bls"
)

// GenRandomBytes generates byte array with random data
func GenRandomBytes(size int) (blk []byte) {
	blk = make([]byte, size)
	_, _ = rand.Reader.Read(blk)
	return
}

// GenerateRandomKeys creates an array of random private and their corresponding public keys
func GenerateRandomKeys(total int) ([]bls.PrivateKey, []bls.PublicKey) {
	privs, pubs := make([]bls.PrivateKey, total), make([]bls.PublicKey, total)
	for i := 0; i < total; i++ {
		privs[i], pubs[i] = bls.GenerateRandomKey()
	}
	return privs, pubs
}

// AggregateMembershipKeys prepares private "membership keys" for
// participating in threshold signature:
//
// MKi = (A1⋅pk1)×H(P, i) + (A2⋅pk2)×H(P, i) + ...
func AggregateMembershipKeys(privs []bls.PrivateKey, pubs []bls.PublicKey, aggPub bls.PublicKey, coefs []big.Int) []bls.Signature {
	res := make([]bls.Signature, len(pubs))
	for i := 0; i < len(pubs); i++ {
		res[i] = bls.ZeroSignature()
		for j := 0; j < len(pubs); j++ {
			res[i] = res[i].Aggregate(privs[j].GenerateMembershipKeyPart(byte(i), aggPub, coefs[j]))
		}
	}
	return res
}

func signMultisigPartially(
	privs []bls.PrivateKey,
	pubs []bls.PublicKey,
  mks []bls.Signature,
	aggPub bls.PublicKey,
	bitmask *big.Int,
	msg []byte) (bls.PublicKey, bls.Signature) {
	pub := bls.ZeroPublicKey()
	sig := bls.ZeroSignature()
	for i := 0; i < len(pubs); i++ {
		if bitmask.Bit(i) != 0 {
			s := privs[i].Multisign(msg, aggPub, mks[i])
			sig = sig.Aggregate(s)
			pub = pub.Aggregate(pubs[i])
		}
	}
	return pub, sig
}

type Output struct {
  AggregatedPublicKey string `json:"aggregatedPublicKey"`
  PartPublicKey string `json:"partPublicKey"`
  Message string `json:"message"`
  PartSignature string `json:"partSignature"`
  SignersBitmask string `json:"signersBitmask"`
  NumSigners int `json:"numSigners"`
}

func main() {
  var numParticipants int
  var numSigners int
  var messageSize int

  flag.IntVar(&numParticipants, "num-total", -1, "total number of participants in the scheme")
  flag.IntVar(&numSigners, "num-signers", -1, "number of participants who sign the message")
  flag.IntVar(&messageSize, "message-size", -1, "size of message in bytes")

  flag.Parse()

  if numParticipants == -1 || numSigners == -1 || messageSize == -1 {
    flag.Usage()
    os.Exit(1)
  }

  if numParticipants > 64 {
    _ = fmt.Errorf("Can support up to 64 participants, got %d", numParticipants);
    os.Exit(2)
  }

  privs, pubs := GenerateRandomKeys(numParticipants)
  as          := bls.CalculateAntiRogueCoefficients(pubs)
  aggPub      := bls.AggregatePublicKeys(pubs, as)
  mks := AggregateMembershipKeys(privs, pubs, aggPub, as)

  msg         := GenRandomBytes(messageSize)

  for signers := numSigners; signers <= numParticipants; signers++ {
    var mask int64 = (1 << signers) - 1
    bitmask := big.NewInt(mask)

    pub, sig := signMultisigPartially(privs, pubs, mks, aggPub, bitmask, msg)

    output := &Output {
      AggregatedPublicKey: hex.EncodeToString(aggPub.Marshal()),
      PartPublicKey: hex.EncodeToString(pub.Marshal()),
      Message: hex.EncodeToString(msg),
      PartSignature: hex.EncodeToString(sig.Marshal()),
      SignersBitmask: hex.EncodeToString(bitmask.Bytes()),
      NumSigners: signers,
    }

    outputJson, _ := json.Marshal(output)
    fmt.Println(string(outputJson))
  }
}
