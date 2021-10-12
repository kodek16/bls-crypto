package test

import (
	"bls-crypto/bls"
	"bytes"
	"log"
	"math/big"
	"math/bits"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/require"
)

const (
	MESSAGE_SIZE        = 32
	PARTICIPANTS_NUMBER = 64
)

var (
	msg         = GenRandomBytes(MESSAGE_SIZE)
	privs, pubs = GenerateRandomKeys(PARTICIPANTS_NUMBER)
	as          = bls.CalculateAntiRogueCoefficients(pubs)
	aggPub      = bls.AggregatePublicKeys(pubs, as)
	mks         = AggregateMembershipKeys(privs, pubs, aggPub, as)
)

func TestPrecompiled_SimpleAggregatedSignatureInSolidity(t *testing.T) {
	sigs := make([]bls.Signature, PARTICIPANTS_NUMBER)
	for i, priv := range privs {
		sigs[i] = priv.Sign(msg)
	}
	sig := bls.AggregateSignatures(sigs, as)
	_, err := blsSignatureTest.VerifySignature(owner, aggPub.Marshal(), msg, sig.Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_SignAsPointInSolidity(t *testing.T) {
	var data []byte
	data = append(data, pubs[0].Marshal()...)
	dat := make([]byte, 32)
	dat[31] = 42
	data = append(data, dat...)
	sig := privs[0].Sign(data)
	msgPoint := bls.HashToPointIndex(pubs[0], 42)
	_, err := blsSignatureTest.VerifySignaturePoint(owner, pubs[0].Marshal(), msgPoint.Marshal(), sig.Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_MembershipKeysInSolidity(t *testing.T) {
	msgPoint := bls.HashToPointIndex(aggPub, 0)
	_, err := blsSignatureTest.VerifySignaturePoint(owner, aggPub.Marshal(), msgPoint.Marshal(), mks[0].Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_AggregatedHashInSolidity(t *testing.T) {
	index := byte(42)
	dataBytes, err := blsSignatureTest.VerifyAggregatedHash(&bind.CallOpts{}, aggPub.Marshal(), big.NewInt(int64(index)))
	require.NoError(t, err)
	res := bls.HashToPointIndex(aggPub, index)
	require.Equal(t, 0, bytes.Compare(dataBytes, res.Marshal()))
}

// signMultisigPartially signs BLS multisignarure by only the specified members
func signMultisigPartially(bitmask *big.Int) (bls.PublicKey, bls.Signature) {
	pub := bls.ZeroPublicKey()
	sig := bls.ZeroSignature()
	for i := 0; i < len(pubs); i++ {
		if bitmask.Bit(i) != 0 {
			s := privs[i].Multisign(msg, aggPub, mks[i])
			sig.Aggregate(s)
			pub.Aggregate(pubs[i])
		}
	}
	return pub, sig
}

func verifyMultisigTest(t *testing.T, mask int64) {
	bitmask := big.NewInt(mask)
	pub, sig := signMultisigPartially(bitmask)

	// verify in solidity
	tx, err := blsSignatureTest.VerifyMultisignature(owner, aggPub.Marshal(), pub.Marshal(), msg, sig.Marshal(), bitmask)
	require.NoError(t, err)
	log.Printf("Signers: %3d/%d, gas: %d", bits.OnesCount64(uint64(mask)), len(pubs), tx.Gas())
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)

	// verify in golang code as well
	require.True(t, sig.VerifyMultisig(aggPub, pub, msg, bitmask))
}

func Test_KofNVerifyAggregatedManual(t *testing.T) {
	if len(pubs) < 256 {
		t.Skip("This test needs 256 or more PARTICIPANTS_NUMBER. Skipping.")
	}
	bitmask := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))
	//log.Println(bitmask.Text(16))

	pub, sig := signMultisigPartially(bitmask)
	tx, err := blsSignatureTest.VerifyMultisignature(owner, aggPub.Marshal(), pub.Marshal(), msg, sig.Marshal(), bitmask)
	require.NoError(t, err)
	log.Printf("Signers: %d, gas: %d", len(pubs), tx.Gas())
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)

	//bitmask = new(big.Int).SetBit(bitmask, 0, 0)
	require.True(t, sig.VerifyMultisig(aggPub, pub, msg, bitmask))
}

func TestPrecompiled_Verify63MultisigInSolidity(t *testing.T) {
	if len(pubs) < 63 {
		t.Skip("This test needs 63 or more PARTICIPANTS_NUMBER. Skipping.")
	}
	verifyMultisigTest(t, 0x7FFFFFFFFFFFFFFF)
}

func TestPrecompiled_Verify32MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0xFFFFFFFF)
}

func TestPrecompiled_Verify17MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0xF0F0F0F1)
}

func TestPrecompiled_Verify16MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x0F0F0F0F)
}

func TestPrecompiled_Verify8MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x11111111)
}

func TestPrecompiled_Verify4MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x10101010)
}

func TestPrecompiled_Verify2MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 0x80000001)
}

func TestPrecompiled_Verify1MultisigInSolidity(t *testing.T) {
	verifyMultisigTest(t, 1)
}
