package test

import (
	"bytes"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

var (
	message   = GenRandomBytes(5000)
	secretKey = new(big.Int).SetBytes(GenRandomBytes(64))
	publicKey = new(bn256.G2).ScalarBaseMult(secretKey)
	signature = Sign(secretKey, message)
	pubBytes  = publicKey.Marshal()
	sigBytes  = signature.Marshal()
	data      = PreparePoints(message, publicKey, signature)
)

func TestPrecompiled_VerifySignatureInSolidity(t *testing.T) {
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_VerifyPreparedBytes(t *testing.T) {
	_, err := blsSignatureTest.VerifyBytes(owner, data)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_GetBytesFromParams(t *testing.T) {
	dataBytes, err := blsSignatureTest.GetBytesFromParams(&bind.CallOpts{}, pubBytes, message, sigBytes)
	require.NoError(t, err)
	require.Equal(t, 0, bytes.Compare(data, dataBytes))
}

func TestPrecompiled_FailWrongSignatureInSolidity(t *testing.T) {
	message[31] = 9
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.False(t, verifiedSol)
}
