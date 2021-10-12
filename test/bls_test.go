package test

import (
	"bls-crypto/bls"
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/stretchr/testify/require"
)

var (
	message              = GenRandomBytes(5000)
	secretKey, publicKey = bls.GenerateRandomKey()
	signature            = secretKey.Sign(message)
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
	sk, _ := GenerateRandomKeys(2)
	p1 := sk[0].Sign(message)
	p2 := sk[1].Sign(message)
	dataBytes, err := blsSignatureTest.AddOnCurveE1(&bind.CallOpts{}, p1.Marshal(), p2.Marshal())
	require.NoError(t, err)
	p2.Aggregate(p1)
	require.Equal(t, 0, bytes.Compare(dataBytes, p2.Marshal()))
}

func TestPrecompiled_FailWrongSignatureInSolidity(t *testing.T) {
	message[31] = 9
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.False(t, verifiedSol)
}
