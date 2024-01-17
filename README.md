# VectorX
Implementation of zero-knowledge proof circuits for [Vector](https://blog.availproject.org/data-attestation-bridge/), Avail's Data Attestation Bridge.

## Overview
Vector X's core contract is `VectorX`, which stores commitments to ranges of data roots and state
roots from Avail blocks.

## Deployment
The circuits are available on Succinct X [here](https://platform.succinct.xyz/succinctlabs/vectorx).

Vector X is currently deployed for Avail's Goldberg testnet on Holesky [here](https://holesky.etherscan.io/address/0x17156d52c0707cde305661ba45457afc23d851e0#events).

## Integrate
Get the genesis parameters for the `VectorX` contract with a specific Avail block (with no input defaults to block 1).
```
cargo run --bin genesis -- --block 100
```

Update `contracts/.env` following `contracts/.env.example`.

Deploy the `VectorX` contract with genesis parameters.

In `contracts/`, run
```
forge install

source .env

forge script script/Deploy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

Update `.env` following `.env.example`.

Run `VectorX` script to update the LC continuously.

In `/`, run
```
cargo run --bin vectorx
```

### Reset the Contract
Get the new genesis parameters for the `VectorX` contract with a specific Avail block (with no input defaults to block 1).
```
cargo run --bin genesis -- --block 100
```

Update `contracts/.env` following `contracts/.env.example`.

Deploy the `VectorX` contract with genesis parameters.

In `contracts/`, run
```
forge install

source .env

forge script script/Reinitialize.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

## Avail Indexer
Avail does not currently store justifications for non-era end blocks on archive nodes, so the 
following service indexes Avail and stores the ephermal justifications, which are used for `step` 
proofs.

### Run the Indexer
```
cargo run --bin indexer
```

## Avail Merkle Proof Service
Whenever a new data root commitment is stored on-chain, the merkle proofs need to be made available for end-users to prove the data root's of blocks within those data commitments. This service listens for data root commitment events on-chain and stores the merkle proofs for each data root in the range, which is then exposed via a separate endpoint.

### Run the Merkle Proof Service
```
cargo run --bin events
```

### Query for a `dataRoot` Proof
Example of querying for the merkle proof data for Goldberg testnet block 156961.
```
curl https://beaconapi.succinct.xyz/api/integrations/vectorx/156961
```
