package test

import (
	"bytes"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/stretchr/testify/require"
)

const TOTAL_KEYS = 255

var (
	privs, pubs = GenRandomKeys(TOTAL_KEYS)
	msg         = GenRandomBytes(5000)
)

func TestPrecompiled_NofNAggregatedSignatureInSolidity(t *testing.T) {
	sig := Sign(privs[0], msg)
	for i := 1; i < TOTAL_KEYS; i++ {
		sgn := Sign(privs[i], msg)
		sig = new(bn256.G1).Add(sig, sgn)
	}
	pub := AggregatePointsOnG2(pubs)
	log.Println("Aggregated public key", pub.String())
	log.Println("Aggregated signature", sig.String())
	_, err := blsSignatureTest.VerifySignature(owner, pub.Marshal(), msg, sig.Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_AggregatedHashInSolidity(t *testing.T) {
	p := new(bn256.G2).ScalarBaseMult(new(big.Int).SetBytes(GenRandomBytes(64)))
	index := byte(42)
	dataBytes, err := blsSignatureTest.VerifyAggregatedHash(&bind.CallOpts{}, p.Marshal(), big.NewInt(int64(index)))
	require.NoError(t, err)
	res := HashToPointByte(p, index)
	require.Equal(t, 0, bytes.Compare(dataBytes, res.Marshal()))
}

func TestPrecompiled_2of2VerifyAggregatedInSolidity(t *testing.T) {
	s1 := new(big.Int).SetBytes(GenRandomBytes(64))
	p1 := new(bn256.G2).ScalarBaseMult(s1)
	s2 := new(big.Int).SetBytes(GenRandomBytes(64))
	p2 := new(bn256.G2).ScalarBaseMult(s2)
	p := new(bn256.G2).Add(p1, p2)
	mk11 := new(bn256.G1).ScalarMult(HashToPointByte(p, 0), s1)
	mk12 := new(bn256.G1).ScalarMult(HashToPointByte(p, 1), s1)
	mk1 := new(bn256.G1).Add(mk11, mk12)
	mk21 := new(bn256.G1).ScalarMult(HashToPointByte(p, 0), s2)
	mk22 := new(bn256.G1).ScalarMult(HashToPointByte(p, 1), s2)
	mk2 := new(bn256.G1).Add(mk21, mk22)
	sig1 := SignAggregated(s1, msg, p, mk1)
	sig2 := SignAggregated(s2, msg, p, mk2)
	sig := new(bn256.G1).Add(sig1, sig2)
	bitmask := big.NewInt(3)

	_, err := blsSignatureTest.VerifyAggregatedSignature(owner, p.Marshal(), p.Marshal(), msg, sig.Marshal(), bitmask)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}
