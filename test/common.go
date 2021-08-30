package test

import (
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/keep-network/keep-core/pkg/altbn128"
	"math/big"
	"math/rand"
	"time"
)

func GetBytesFromPoints(g1Points []*bn256.G1, g2Points []*bn256.G2) (data []byte) {
	if len(g1Points) != len(g2Points) {
		panic("input slices have different lengths")
	}
	for i, g1 := range g1Points {
		data = append(data, g1.Marshal()...)
		data = append(data, g2Points[i].Marshal()...)
	}
	return
}

func PreparePoints(message []byte, publicKey *bn256.G2, signature *bn256.G1) []byte {
	p2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))
	msgPoint := altbn128.G1HashToPoint(message)
	a := []*bn256.G1{
		new(bn256.G1).Neg(signature),
		msgPoint,
	}
	b := []*bn256.G2{
		p2,
		publicKey,
	}
	data := GetBytesFromPoints(a, b)
	return data
}

func GenRandomBytes(size int) (blk []byte) {
	rand.Seed(time.Now().UnixNano())
	blk = make([]byte, size)
	_, _ = rand.Read(blk)
	return
}

// Sign creates a point on a curve G1 by hashing and signing provided message
// using the provided secret key.
func Sign(secretKey *big.Int, message []byte) *bn256.G1 {
	return SignG1(secretKey, altbn128.G1HashToPoint(message))
}

// SignG1 creates a point on a curve G1 by signing the provided
// G1 point message using the provided secret key.
func SignG1(secretKey *big.Int, message *bn256.G1) *bn256.G1 {
	return new(bn256.G1).ScalarMult(message, secretKey)
}

// Verify performs the pairing operation to check if the signature is correct
// for the provided message and the corresponding public key.
func Verify(publicKey *bn256.G2, message []byte, signature *bn256.G1) bool {
	return VerifyG1(publicKey, altbn128.G1HashToPoint(message), signature)
}

// VerifyG1 performs the pairing operation to check if the signature is correct
// for the provided G1 point message and the corresponding public key.
func VerifyG1(publicKey *bn256.G2, message *bn256.G1, signature *bn256.G1) bool {
	// Generator point of G2 group.
	p2 := new(bn256.G2).ScalarBaseMult(big.NewInt(1))

	a := []*bn256.G1{new(bn256.G1).Neg(signature), message}
	b := []*bn256.G2{p2, publicKey}

	return bn256.PairingCheck(a, b)
}
