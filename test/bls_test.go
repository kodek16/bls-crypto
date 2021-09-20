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
	log.Println("Aggregated public key", publicKey.String())
	log.Println("Aggregated signature", signature.String())
	_, err := blsSignatureTest.VerifySignature(owner, pubBytes, message, sigBytes)
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_VerifyAggregatedSignatureInSolidity(t *testing.T) {
	for i := 0; i < 1000; i++ {
		secretKey2 := new(big.Int).SetBytes(GenRandomBytes(64))
		publicKey2 := new(bn256.G2).ScalarBaseMult(secretKey2)
		signature2 := Sign(secretKey2, message)
		publicKey = new(bn256.G2).Add(publicKey, publicKey2)
		signature = new(bn256.G1).Add(signature, signature2)
	}
	log.Println("Aggregated public key", publicKey.String())
	log.Println("Aggregated signature", signature.String())
	_, err := blsSignatureTest.VerifySignature(owner, publicKey.Marshal(), message, signature.Marshal())
	require.NoError(t, err)
	backend.Commit()
	verifiedSol, err := blsSignatureTest.Verified(&bind.CallOpts{})
	require.True(t, verifiedSol)
}

func TestPrecompiled_AddInSolidity(t *testing.T) {
	k1 := new(big.Int).SetBytes(GenRandomBytes(64))
	p1 := new(bn256.G1).ScalarBaseMult(k1)
	k2 := new(big.Int).SetBytes(GenRandomBytes(64))
	p2 := new(bn256.G1).ScalarBaseMult(k2)
	dataBytes, err := blsSignatureTest.TestAdditionOnCurveE1(&bind.CallOpts{}, p1.Marshal(), p2.Marshal())
	require.NoError(t, err)

	res := new(bn256.G1).Add(p2, p1)
	require.Equal(t, 0, bytes.Compare(dataBytes, res.Marshal()))
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
