package test

import (
	"github.com/eywa-protocol/bls-crypto/bls"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_EncryptDecrypt(t *testing.T) {
	pass := "password"
	priv0, _ := bls.GenerateRandomKey()

	protectedKey, err := priv0.Encrypt(pass)
	require.NoError(t, err)
	t.Log(protectedKey)

	decr, err := bls.Decrypt([]byte(protectedKey), pass)
	require.NoError(t, err)
	require.Equal(t, decr, priv0.Marshal())

}
