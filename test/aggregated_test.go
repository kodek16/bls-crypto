package test

import (
	"bls-crypto/bls"
	"bytes"
	"math/big"
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
)

func Test_AggregatedSignature(t *testing.T) {
	priv1, pub1 := bls.GenerateRandomKey()
	priv2, pub2 := bls.GenerateRandomKey()
	priv3, pub3 := bls.GenerateRandomKey()
	sig1 := priv1.Sign(msg)
	sig2 := priv2.Sign(msg)
	sig3 := priv3.Sign(msg)

	require.True(t, sig1.Aggregate(sig2).Aggregate(sig3).Verify(pub1.Aggregate(pub2).Aggregate(pub3), msg))
}

func Test_AggregatedSignatureInSolidity(t *testing.T) {
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

func Test_SignAsPointInSolidity(t *testing.T) {
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

func Test_AggregatedHashInSolidity(t *testing.T) {
	index := byte(42)
	dataBytes, err := blsSignatureTest.VerifyAggregatedHash(&bind.CallOpts{}, aggPub.Marshal(), big.NewInt(int64(index)))
	require.NoError(t, err)
	res := bls.HashToPointIndex(aggPub, index)
	require.Equal(t, 0, bytes.Compare(dataBytes, res.Marshal()))
}
