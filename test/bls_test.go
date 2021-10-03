package test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/stretchr/testify/require"
)

var (
	message              = GenRandomBytes(5000)
	secretKey, publicKey = GenRandomKey()
	signature            = Sign(secretKey, message)
	pubBytes             = publicKey.Marshal()
	sigBytes             = signature.Marshal()
)

func TestPrecompiled_VerifySignatureInSolidity(t *testing.T) {
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_AddInSolidity(t *testing.T) {
	sk, _ := GenRandomKeys(2)
	p1 := Sign(sk[0], message)
	p2 := Sign(sk[1], message)
	dataBytes, err := blsSignatureTest.AddOnCurveE1(&bind.CallOpts{}, p1.Marshal(), p2.Marshal())
	require.NoError(t, err)
	res := new(bn256.G1).Add(p2, p1)
	require.Equal(t, 0, bytes.Compare(dataBytes, res.Marshal()))
}

func TestPrecompiled_FailWrongSignatureInSolidity(t *testing.T) {
	message[31] = 9
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.False(t, verifiedSol)
}
