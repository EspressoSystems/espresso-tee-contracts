#!/usr/bin/env bash
set -euo pipefail

# Deploys a fresh SP1Verifier (currently v6.1.0) and verifies it on Etherscan.
# Runs from inside lib/aws-nitro-enclave-attestation/contracts/ so the Automata
# foundry profile (solc 0.8.27, opt 200, no via_ir) is used — this is what makes
# verification succeed. Running from this repo's root deploys un-verifiable bytecode.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/lib/aws-nitro-enclave-attestation/contracts"

if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

: "${RPC_URL:?RPC_URL is not set. Add it to .env or export it.}"
: "${PRIVATE_KEY:?PRIVATE_KEY is not set. Add it to .env or export it.}"
: "${CHAIN_ID:?CHAIN_ID is not set. Add it to .env or export it.}"
: "${ETHERSCAN_API_KEY:?ETHERSCAN_API_KEY is not set. Add it to .env or export it.}"

cd "$CONTRACTS_DIR"

OUTPUT=$(forge create \
    lib/sp1-contracts/contracts/src/v6.1.0/SP1VerifierGroth16.sol:SP1Verifier \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --chain "$CHAIN_ID")

ADDR=$(echo "$OUTPUT" | grep 'Deployed to:' | awk '{print $3}')
echo "SP1Verifier deployed at: $ADDR"
