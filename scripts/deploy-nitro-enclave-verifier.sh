#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/lib/aws-nitro-enclave-attestation/contracts"

if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

# Validate environment
: "${RPC_URL:?RPC_URL is not set. Add it to .env or export it.}"
: "${PRIVATE_KEY:?PRIVATE_KEY is not set. Add it to .env or export it.}"
: "${CHAIN_ID:?CHAIN_ID is not set. Add it to .env or export it.}"
: "${ETHERSCAN_API_KEY:?ETHERSCAN_API_KEY is not set. Add it to .env or export it.}"

if [ ! -d "$CONTRACTS_DIR" ]; then
    echo "Error: aws-nitro-enclave-attestation submodule not found at $CONTRACTS_DIR"
    echo "Run: git submodule update --init --recursive"
    exit 1
fi

cd "$CONTRACTS_DIR"

RESOLVED_CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
if [ "$RESOLVED_CHAIN_ID" != "$CHAIN_ID" ]; then
    echo "Warning: CHAIN_ID ($CHAIN_ID) does not match RPC chain ($RESOLVED_CHAIN_ID)"
    exit 1
fi

OWNER_ADDRESS=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "Deployer / Owner address: $OWNER_ADDRESS"

# maxTimeDiff from the submodule's deploy-config.json (3 hours = 10800 seconds)
MAX_TIME_DIFF=10800

echo ""
echo "=== Deploying NitroEnclaveVerifier (chain ${CHAIN_ID}) ==="
echo "  owner:       $OWNER_ADDRESS"
echo "  maxTimeDiff: $MAX_TIME_DIFF"

VERIFIER_OUTPUT=$(forge create \
    src/NitroEnclaveVerifier.sol:NitroEnclaveVerifier \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --chain "$CHAIN_ID" \
    --constructor-args "$OWNER_ADDRESS" "$MAX_TIME_DIFF" "[]")

VERIFIER_ADDRESS=$(echo "$VERIFIER_OUTPUT" | grep 'Deployed to:' | awk '{print $3}')
echo "NitroEnclaveVerifier deployed at: $VERIFIER_ADDRESS"

SP1_ADDRESS=""
echo "=== Deploying SP1Verifier (chain ${CHAIN_ID}) ==="
SP1_OUTPUT=$(forge create \
    lib/sp1-contracts/contracts/src/v5.0.0/SP1VerifierGroth16.sol:SP1Verifier \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --chain "$CHAIN_ID")

SP1_ADDRESS=$(echo "$SP1_OUTPUT" | grep 'Deployed to:' | awk '{print $3}')
echo "SP1Verifier deployed at: $SP1_ADDRESS"
