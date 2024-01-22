# VectorX
Implementation of zero-knowledge proof circuits for [Vector](https://blog.availproject.org/data-attestation-bridge/), Avail's Data Attestation Bridge.

## Overview
Vector X's core contract is `VectorX`, which stores commitments to ranges of data roots and state
roots from Avail blocks.

## Deployment
The circuits are available on Succinct X [here](https://platform.succinct.xyz/succinctlabs/vectorx).

Vector X is currently deployed for Avail's Goldberg testnet on Sepolia [here](https://sepolia.etherscan.io/address/0x5ac10644a873AAcd288775A90d6D0303496A4304#events).

## Run the VectorX Light Client
Get the genesis parameters for the `VectorX` contract with a specific Avail block (with no input defaults to block 1).
```
cargo run --bin genesis -- --block 240000
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

### Run the Merkle Proof Indexer Service
```
cargo run --bin events
```

### Query for `dataRoot` Proof Data
Example of querying for the merkle proof data for Goldberg testnet block 248490 from the VectroX contract
deployed on Sepolia (chainId 11155111) at address 0x5ac10644a873AAcd288775A90d6D0303496A4304.
```
curl https://beaconapi.succinct.xyz/api/integrations/vectorx?chainName=goldberg&contractChainId=11155111&contractAddress=0x5ac10644a873AAcd288775A90d6D0303496A4304&blockNumber=248490
```

## Dummy VectorX Set-Up
If you do not want to generate proofs for the `VectorX` light client, you can use `DummyVectorX` instead with dummy circuits that do not require any intensive proof generation. You can deploy the DummyVectorX contract with the same genesis parameters as the VectorX contract and re-initialize the light client using the following commands. Ensure you are using the dummy function IDs for [`dummy_rotate`](https://alpha.succinct.xyz/avail/vectorx/releases/10) and [`dummy_step`](https://alpha.succinct.xyz/avail/vectorx/releases/9).

```
forge script script/DeployDummy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY

forge script script/ReinitializeDummy.s.sol --rpc-url $ETHEREUM_RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```
