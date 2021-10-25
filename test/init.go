package test

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/eywa-protocol/bls-crypto/wrappers"
)

var (
	backend                               *backends.SimulatedBackend
	owner                                 *bind.TransactOpts
	blsSignatureTest                      *wrappers.BlsSignatureTest
	err                                   error
	ownerKey                              *ecdsa.PrivateKey
	ownerAddress, blsSignatureTestAddress common.Address
)

func init() {
	ownerKey, _ = crypto.GenerateKey()

	ownerAddress = crypto.PubkeyToAddress(ownerKey.PublicKey)

	genesis := core.GenesisAlloc{
		ownerAddress: {Balance: new(big.Int).SetInt64(math.MaxInt64)},
	}
	backend = backends.NewSimulatedBackend(genesis, math.MaxInt64)

	owner, err = bind.NewKeyedTransactorWithChainID(ownerKey, big.NewInt(1337))
	if err != nil {
		panic(err)
	}

	blsSignatureTestAddress, _, blsSignatureTest, err = wrappers.DeployBlsSignatureTest(owner, backend)
	if err != nil {
		panic(err)
	}

	backend.Commit()
}
