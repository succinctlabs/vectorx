USAGE="Usage: ./update_genesis_state.sh <chain_ids>\n  Example: ./update_genesis_state.sh \"5 420 84531 421613\""

if [ -z "$1" ]; then
	echo $USAGE
	exit 1
fi

IFS=' ' read -r -a CHAIN_IDS <<< "$1"

# Load environment variables from .env
source .env

# Create .env.deployments if it doesn't exist
if [ ! -f .env.deployments ]; then
    touch .env.deployments
fi

echo "Updating genesis state for contracts on chains ${CHAIN_IDS[*]}"


for chain_id in "${CHAIN_IDS[@]}"; do
    rpc_var=$(echo 'RPC_'"${chain_id}")
    rpc=$(echo $(eval echo "\$$rpc_var"))
    etherscan_key_var=$(echo 'ETHERSCAN_API_KEY_'"${chain_id}")
    etherscan_key=$(echo $(eval echo "\$$etherscan_key_var"))

    echo "Running script Deploy${contract} on chain $chain_id"
    forge script Deploy${contract} --rpc-url $rpc --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $etherscan_key
done
