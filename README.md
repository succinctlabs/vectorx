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
    "dataCommitment": "0xcaf4ffea1a32541327ecff021f3794eda7a6d3b24849c852d9b5118854f49fd5",
    "merkleBranch": [
      "0xdf68ba9b2ebf98303909688ad6a9ae3671e5f91b3f0beffdedeb106e3ff5aba2",
      "0x2071b56820d44027691b37fe1b0a43d241b01b46dcc638a8d985998b69499090",
      "0x45a07b99b1491ec7b4cd4965a9d9eb1031f8668c6b64d20768239ccd2bb437aa",
      "0xb6ad5b859800aa54ed22250fc5c2a8d1dc916d3f3e57d713bb25bc9b8bd50a74",
      "0x01c30551f619079565fc89dcc1f3f259a1cd8b6e44aba7d9f42f0406e96689fb",
      "0x178a3caead2a150f2477b9657ebfbc239b2a385817d61134a40aa97651aee38d",
      "0x12c13409b858e2224bdee9a44a23abce2ccea875bc92df8e5520a7bc3ae99228",
      "0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"
    ],
    "index": 0,
    "totalLeaves": 256,
    "dataRoot": "0xa9fc37b017618cf0a7d4ae4935178c63e8206d76eab3f3322d12e746d3fbee03",
    "blockHash": "0x7f7f777f4a876d76b71615c329ece9c77ec582398cd92d381ae0257795336849"
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
    "merkleBranch": [
      "0xdf68ba9b2ebf98303909688ad6a9ae3671e5f91b3f0beffdedeb106e3ff5aba2",
      "0x2071b56820d44027691b37fe1b0a43d241b01b46dcc638a8d985998b69499090",
      "0x45a07b99b1491ec7b4cd4965a9d9eb1031f8668c6b64d20768239ccd2bb437aa",
      "0xb6ad5b859800aa54ed22250fc5c2a8d1dc916d3f3e57d713bb25bc9b8bd50a74",
      "0x01c30551f619079565fc89dcc1f3f259a1cd8b6e44aba7d9f42f0406e96689fb",
      "0x178a3caead2a150f2477b9657ebfbc239b2a385817d61134a40aa97651aee38d",
      "0x12c13409b858e2224bdee9a44a23abce2ccea875bc92df8e5520a7bc3ae99228",
      "0x87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"
    ],
    "index": 0,
    "totalLeaves": 256,
    "dataRoot": "0xa9fc37b017618cf0a7d4ae4935178c63e8206d76eab3f3322d12e746d3fbee03",
    "blockHash": "0x7f7f777f4a876d76b71615c329ece9c77ec582398cd92d381ae0257795336849"
  }
}
```

### Range of blocks stored in the `VectorX` contract

Querying for the range of blocks stored in the VectorX contract deployed on Sepolia (chain ID: 11155111) at address 0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201.

```
https://beaconapi.succinct.xyz/api/integrations/vectorx/range?contractChainId=11155111&contractAddress=0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201
```

Example response:

```json
{ "data": { "rangeStart": 444840, "rangeEnd": 448140 } }
```

### Health of the `VectorX` contract

Querying for the health of the VectorX contract deployed on Sepolia (chain ID: 11155111) at address 0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201.

```
https://beaconapi.succinct.xyz/api/integrations/vectorx/health?chainName=goldberg&contractChainId=11155111&contractAddress=0x169e50f09A50F3509777cEf63EC59Eeb2aAcd201
```

Example response:

```json
{ "data": { "ethBlockSinceLastLog": 32, "blocksBehindHead": 81 } }
```

## Dummy VectorX Set-Up

If you do not want to generate proofs for the `VectorX` light client, you can use `RustX` light client proofs instead with dummy circuits that do not require any intensive proof generation. You can deploy the VectorX contract with the same genesis parameters as the VectorX contract and re-initialize the light client with the new dummy function IDs. Ensure you are using the dummy function IDs for [`dummy_rotate`](https://alpha.succinct.xyz/avail/vectorx/releases/10) and [`dummy_step`](https://alpha.succinct.xyz/avail/vectorx/releases/9).
