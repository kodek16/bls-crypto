package test

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/eywa-protocol/bls-crypto/bls"
	"github.com/stretchr/testify/require"
)

type Message struct {
	Privs     []bls.PrivateKey
	Pubs      []bls.PublicKey
	Signs     []bls.Signature
	Mask      *big.Int
	PrivEmpty bls.PrivateKey
	PubEmpty  bls.PublicKey
	SignEmpty bls.Signature
	MaskEmpty *big.Int
}

func Test_MarshallUnmarshallJson(t *testing.T) {
	N := 3
	privs, pubs := GenerateRandomKeys(N)
	signs := make([]bls.Signature, N)
	for i, priv := range privs {
		signs[i] = priv.Sign(msg)
	}

	outmsg := Message{
		Privs: privs,
		Pubs:  pubs,
		Signs: signs,
		Mask:  big.NewInt(0xCAFEBABE),
	}
	raw, err := json.Marshal(outmsg)
	require.NoError(t, err)
	//log.Print(string(raw))

	var inmsg Message
	err = json.Unmarshal(raw, &inmsg)
	require.NoError(t, err)
	for i, _ := range inmsg.Privs {
		require.Equal(t, 0, bytes.Compare(inmsg.Privs[i].Marshal(), privs[i].Marshal()))
		require.Equal(t, 0, bytes.Compare(inmsg.Pubs[i].Marshal(), pubs[i].Marshal()))
		require.Equal(t, 0, bytes.Compare(inmsg.Signs[i].Marshal(), signs[i].Marshal()))
	}
	require.Equal(t, []byte("0"), inmsg.PrivEmpty.Marshal())
	require.Equal(t, inmsg.PubEmpty.Marshal(), outmsg.PubEmpty.Marshal())
	require.Equal(t, inmsg.SignEmpty.Marshal(), outmsg.SignEmpty.Marshal())
}
