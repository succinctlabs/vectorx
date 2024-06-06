# VectorX

Implementation of zero-knowledge proof circuits for [Vector](https://blog.availproject.org/data-attestation-bridge/), Avail's Data Attestation Bridge.

## Overview

Vector X's core contract is `VectorX`, which stores commitments to ranges of data roots and state
roots from Avail blocks.

The circuits are available on the Succinct Platform [here](https://platform.succinct.xyz/succinctlabs/vectorx).

## Deployment

VectorX's current maintained contract deployments are listed below.

| Src            | Dest       | Contract                                                                                           |
|----------------|------------|----------------------------------------------------------------------------------------------------|
| Hex Devnet     | Sepolia    | [0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75](https://sepolia.etherscan.io/address/0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75#events)                     |
| Hex Devnet     | Arb Sepolia| [0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75](https://sepolia.arbiscan.io/address/0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75#events) |
| Turing Testnet | Sepolia    | [0xe542db219a7e2b29c7aeaeace242c9a2cd528f96](https://sepolia.etherscan.io/address/0xe542db219a7e2b29c7aeaeace242c9a2cd528f96#events)                         |
| Turing Testnet | Arb Sepolia    | [0xA712dfec48AF3a78419A8FF90fE8f97Ae74680F0](https://sepolia.arbiscan.io/address/0xA712dfec48AF3a78419A8FF90fE8f97Ae74680F0#events)                         |


## Run the VectorX Light Client

Get the genesis parameters for the `VectorX` contract.

```
cargo run --bin genesis
```

Update `contracts/.env` following `contracts/README.md`.

Deploy the `VectorX` contract with genesis parameters.

In `contracts/`, run

```
forge install

source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

Update `.env` following `.env.example`.

Run `VectorX` script to update the LC continuously.

In `/`, run

```
cargo run --bin vectorx
```

## Avail Indexer

Avail does not currently store justifications for non-era end blocks on archive nodes, so the
following service indexes Avail and stores the ephermal justifications, which are used for `header_range`
proofs.

### Run the Indexer

```
cargo run --bin indexer
```

## Avail Merkle Proof Service

Whenever a new data root commitment is stored on-chain, the merkle proofs need to be made available for end-users to prove the data root's of blocks within those data commitments. This service listens for data root commitment events on-chain and stores the merkle proofs for each data root in the range, which is then exposed via a separate endpoint. You can configure the contracts to index with `deployments.json`.

### Run the Merkle Proof Indexer Service

```
cargo run --bin events
```

## RPC Queries

### Query for `dataRoot` Proof Data

Querying with a block number.

```
https://beaconapi.succinct.xyz/api/integrations/vectorx?chainName=goldberg&contractChainId=11155111&contractAddress=0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201&blockNumber=444841
```

Example response:

```json
{
  "data": {
    "blockNumber": 444841,
    "rangeHash": "0x4fec90e517f92a0b3d1aa0013b55eac4e7afa1eff13baec2e4e7a105de412302",
    ...
  }
}
```

Querying with a block hash.

```
https://beaconapi.succinct.xyz/api/integrations/vectorx?chainName=goldberg&contractChainId=11155111&contractAddress=0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201&blockHash=0x7f7f777f4a876d76b71615c329ece9c77ec582398cd92d381ae0257795336849
```

Example response:

```json
{
  "data": {
    "rangeHash": "0x4fec90e517f92a0b3d1aa0013b55eac4e7afa1eff13baec2e4e7a105de412302",
    "dataCommitment": "0xcaf4ffea1a32541327ecff021f3794eda7a6d3b24849c852d9b5118854f49fd5",
    ...
  }
}
```

### Health of the `VectorX` contract

Querying for the health of the VectorX contract deployed on Sepolia (chain ID: 11155111) at address 0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201.

```
https://beaconapi.succinct.xyz/api/integrations/vectorx/health?chainName=goldberg&contractChainId=11155111&contractAddress=0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201
```

Example response:

```json
{"data":{"logEmitted":true,"ethBlocksSinceLastLog":35,"lastLogTimestamp":1717707768,"blocksBehindHead":50}}
```

Note: If `logEmitted` is false, the contract has not emitted a log in at least the last `ethBlocksSinceLastLog` blocks.

## Dummy VectorX Set-Up

If you do not want to generate proofs for the `VectorX` light client, you can use `RustX` light client proofs instead with dummy circuits that do not require any intensive proof generation. You can deploy the VectorX contract with the same genesis parameters as the VectorX contract and re-initialize the light client with the new dummy function IDs. Ensure you are using the dummy function IDs for [`dummy_rotate`](https://alpha.succinct.xyz/avail/vectorx/releases/10) and [`dummy_header_range`](https://alpha.succinct.xyz/avail/vectorx/releases/9).
