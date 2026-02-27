#!/usr/bin/env bash
# Deploys the NitroEnclaveVerifier and SP1Verifier contracts
# from the aws-nitro-enclave-attestation submodule.
#
# Usage:
#   ./scripts/deploy-nitro-enclave-verifier.sh [--force]
#
# Options:
#   --force   Deploy even if the submodule already has a deployment record
#             for the target chain (temporarily hides the existing record).
#
# Reads RPC_URL, PRIVATE_KEY, CHAIN_ID, and ETHERSCAN_API_KEY from .env in the project root.

set -euo pipefail

FORCE=false
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=true ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/lib/aws-nitro-enclave-attestation/contracts"

# Source .env from project root if it exists
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

# Resolve chain ID for the deployment JSON lookup
RESOLVED_CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
if [ "$RESOLVED_CHAIN_ID" != "$CHAIN_ID" ]; then
    echo "Warning: CHAIN_ID ($CHAIN_ID) does not match RPC chain ($RESOLVED_CHAIN_ID)"
    exit 1
fi
DEPLOY_FILE="deployments/${CHAIN_ID}.json"
BACKUP_FILE=""

# If --force, temporarily hide the existing deployment record so the
# Solidity script's needsRedeploy() check doesn't skip deployment.
if $FORCE && [ -f "$DEPLOY_FILE" ]; then
    BACKUP_FILE="${DEPLOY_FILE}.bak"
    echo "Force mode: temporarily moving $DEPLOY_FILE aside"
    mv "$DEPLOY_FILE" "$BACKUP_FILE"
fi

# Restore the deployment file on exit (success or failure)
cleanup() {
    if [ -n "$BACKUP_FILE" ] && [ -f "$BACKUP_FILE" ]; then
        # If forge created a new deployment file, keep it; otherwise restore.
        if [ ! -f "$DEPLOY_FILE" ]; then
            mv "$BACKUP_FILE" "$DEPLOY_FILE"
            echo "Restored original $DEPLOY_FILE"
        else
            rm "$BACKUP_FILE"
        fi
    fi
}
trap cleanup EXIT

echo "=== Deploying NitroEnclaveVerifier (chain ${CHAIN_ID}) ==="
forge script script/NitroEnclaveVerifier.s.sol \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --verifier etherscan --chain "$CHAIN_ID" \
    --sig 'deployVerifier()'

echo ""
echo "=== Deploying SP1Verifier ==="
forge script script/NitroEnclaveVerifier.s.sol \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --verifier etherscan --chain "$CHAIN_ID" \
    --sig 'deploySP1Verifier()'

echo ""
echo "=== Done ==="
echo "Deployment artifacts saved in: $CONTRACTS_DIR/deployments/"
