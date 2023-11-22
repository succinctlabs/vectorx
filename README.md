# VectorX
Implementation of zero-knowledge proof circuits for [Vector](https://blog.availproject.org/data-attestation-bridge/), Avail's Data Attestation Bridge.

## Overview
Vector X's core contract is `VectorX`, which stores commitments to ranges of data roots and state
roots from Avail blocks.

## Deployment
The circuits are available on Succinct X [here](https://platform.succinct.xyz/succinctlabs/vectorx).

Vector X is currently deployed for Avail's Goldberg testnet on Goerli [here](https://goerli.etherscan.io/address/0xc862F17Ebb256679D8b428634B8D1E5D8d9EBf67#events).

## Integrate
Update `contracts/.env` following `contracts/.env.example`.

Initialize the `VectorX` contract with genesis parameters.
```
forge install

forge script script/Deploy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --verify VectorX --broadcast
```

Update `.env` following `.env.example`.

Run `VectorX` script to update the LC continuously.
```
cargo run --bin vectorx
```

## Avail Indexer
Avail does not currently store justifications for non-era end blocks on archive nodes, so the 
following service indexes Avail and stores the ephermal justifications, which are used for `step` 
proofs.

### Run the Indexer
```
cargo run --bin indexer
```
