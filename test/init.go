package test

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"go-sol-bls/wrappers"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	backend                  *backends.SimulatedBackend
	owner                    *bind.TransactOpts
	blsSignatureTest         *wrappers.BlsSignatureTest
	blsSignatureVerification *wrappers.BlsSignatureVerification
	err                      error
	ownerKey, signerKey      *ecdsa.PrivateKey

	ctx                                   context.Context
	Domain                                map[string]json.RawMessage
	domainChainIDAsString                 map[string]json.RawMessage
	Msg                                   map[string]json.RawMessage
	ownerAddress, blsSignatureTestAddress common.Address
	createNodeData                        *createNodeDataTypw
)

type createNodeDataTypw struct {
	nodeWallet    common.Address
	nodeIdAddress common.Address
	blsPubKey     string
}

func init() {
	ctx = context.Background()

	ownerKey, _ = crypto.GenerateKey()

	signerKey, _ = crypto.GenerateKey()

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
