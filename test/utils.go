package test

import (
	"bls-crypto/bls"
	"crypto/rand"
	"math/big"
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
