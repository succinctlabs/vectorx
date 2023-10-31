# VectorX
## Circuits

## Contracts
### Deploy
```
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args 0x6e4f1e9ea315ebfd69d18c2db974eef6105fb803 --etherscan-api-key $ETHERSCAN_API_KEY --verify VectorX
```
### Test with on-chain requests
```
forge script script/VectorX.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```
### Test with off-chain requests
Add CONTRACT_ADDRESS to .env

```
cargo run --bin vectorx
```
