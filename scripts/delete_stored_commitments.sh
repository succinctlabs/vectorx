# Connect to Upstash
#!/bin/bash

# Check if the correct number of arguments are passed
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <redis_url> <chain_id> <contract_address>"
    exit 1
fi
# Assign arguments to variables
REDIS_URL=$1
CHAIN_ID=$2
CONTRACT_ADDRESS=$(echo $3 | tr '[:upper:]' '[:lower:]')
KEY_TO_DELETE="${CHAIN_ID}:${CONTRACT_ADDRESS}:ranges"

# Connect to Redis and delete the ZSET key
if ! redis-cli -u $REDIS_URL --tls DEL $KEY_TO_DELETE; then
    echo "Failed to delete key: $KEY_TO_DELETE from Redis"
    exit 1
else
    echo "Deleted key: $KEY_TO_DELETE from Redis"
fi
