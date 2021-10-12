# BLS signature and multisignature schemas in Go and Solidity

This code demonstrates the following schemas. Sign functions signature are in GoLang,
verifies are both in Golang and Solidity using Ethereum precompiled callbacks.

#### BLS signature scheme.
1. Alice signs a message.
2. Everyone verifies it using her public key.

#### BLS signature aggregation (n-of-n multisignature).
1. A group of participants sign a message.
2. Their signatures are aggregated into one.
3. Everyone verifies the *aggregated* signature using the *aggregated* public key.

#### Accountable-Subgroup Multisignatures (threshold signatures, m-of-n multisignatures).
1. A subgroup of a group of participants sign a message.
2. Their signatures are aggregated into one.
3. Everyone verifies the *aggregated* signature using
   * the *aggregated* signature,
   * the *aggregated* public key of the subgroup (who really signed),
   * the *aggregated* public key of all participants in the group (whether signed or not),
   * the bitmap representing the subgroup (who really signed) - this is what *accountable* is.


### Inspired by

* https://gist.github.com/BjornvdLaan/ca6dd4e3993e1ef392f363ec27fe74c4
* https://github.com/ConsenSys/gpact/blob/main/common/common/src/main/solidity/BlsSignatureVerification.sol
* https://github.com/keep-network/keep-core/blob/main/solidity/contracts/cryptography/AltBn128.sol


### References

1. Dan Boneh, Manu Drijvers, and Gregory Neven.
   Compact Multi-Signatures for Smaller Blockchains.
   https://crypto.stanford.edu/~dabo/pubs/abstracts/ASM.html
2. BLS signatures: better than Schnorr.
   https://medium.com/cryptoadvance/bls-signatures-better-than-schnorr-5a7fe30ea716
3. Dan Boneh, Victor Shoup.
   A Graduate Course in Applied Cryptography.
   Chapter 15: Elliptic curve cryptography and pairings.
   http://toc.cryptobook.us/
4. EIP-196: Precompiled contracts for addition and scalar multiplication on
   the elliptic curve alt_bn128 
   https://eips.ethereum.org/EIPS/eip-196


### Prerequisites to run tests

1. Install go compiller: v1.16+ https://golang.org/doc/install

2. Install solc: v0.8+ https://docs.soliditylang.org/en/v0.8.6/installing-solidity.html

3. Install abigen:

        cd bls-crypto
        make dep
        cd $GOPATH/pkg/mod/github.com/ethereum/go-ethereum@*
        make devtools


### Run tests

    make test


### Test parameters

Note that there are parameters specified in the
[aggregated_test.go][test/aggregated_test.go] file that affect the gas usage:

* `MESSAGE_SIZE` - size of the message being signed in bytes,
* `PARTICIPANTS_NUMBER` - total number of participants in a group who sign the message.
