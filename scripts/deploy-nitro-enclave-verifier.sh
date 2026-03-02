#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTRACTS_DIR="$PROJECT_ROOT/lib/aws-nitro-enclave-attestation/contracts"
SAMPLES_DIR="$PROJECT_ROOT/lib/aws-nitro-enclave-attestation/samples"

if [ -f "$PROJECT_ROOT/.env" ]; then
    set -a
    source "$PROJECT_ROOT/.env"
    set +a
fi

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
    echo "Error: CHAIN_ID ($CHAIN_ID) does not match RPC chain ($RESOLVED_CHAIN_ID)"
    exit 1
fi

OWNER_ADDRESS=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "Deployer / Owner address: $OWNER_ADDRESS"

# maxTimeDiff from the submodule's deploy-config.json (3 hours = 10800 seconds)
MAX_TIME_DIFF=10800

# ============================================================
# Step 1: Deploy NitroEnclaveVerifier
# ============================================================
echo ""
echo "=== Step 1: Deploying NitroEnclaveVerifier (chain ${CHAIN_ID}) ==="
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

# ============================================================
# Step 2: Deploy SP1Verifier
# ============================================================
echo ""
echo "=== Step 2: Deploying SP1Verifier (chain ${CHAIN_ID}) ==="

SP1_OUTPUT=$(forge create \
    lib/sp1-contracts/contracts/src/v5.0.0/SP1VerifierGroth16.sol:SP1Verifier \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --broadcast \
    --verify --etherscan-api-key "$ETHERSCAN_API_KEY" \
    --chain "$CHAIN_ID")

SP1_ADDRESS=$(echo "$SP1_OUTPUT" | grep 'Deployed to:' | awk '{print $3}')
echo "SP1Verifier deployed at: $SP1_ADDRESS"

# ============================================================
# Step 3: Configure — Set root certificate
# ============================================================
echo ""
echo "=== Step 3: Setting root certificate ==="

ROOT_CERT_FILE="$SAMPLES_DIR/aws_root.der"
if [ ! -f "$ROOT_CERT_FILE" ]; then
    echo "Error: AWS root cert not found at $ROOT_CERT_FILE"
    exit 1
fi

# The contract uses sha256, not keccak — use openssl
ROOT_CERT_HASH=0x$(openssl dgst -sha256 -binary "$ROOT_CERT_FILE" | xxd -p -c 64)
echo "  Root cert SHA-256: $ROOT_CERT_HASH"

cast send "$VERIFIER_ADDRESS" \
    "setRootCert(bytes32)" \
    "$ROOT_CERT_HASH" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY"

echo "Root certificate set."

# ============================================================
# Step 4: Configure — Set SP1 ZK configuration
# ============================================================
echo ""
echo "=== Step 4: Setting SP1 ZK configuration ==="

# SP1 program IDs from the submodule's sample config
SP1_VERIFIER_ID=$(jq -r '.program_id.verifier_id' "$SAMPLES_DIR/sp1_program_id.json")
SP1_AGGREGATOR_ID=$(jq -r '.program_id.aggregator_id' "$SAMPLES_DIR/sp1_program_id.json")
SP1_VERIFIER_PROOF_ID=$(jq -r '.program_id.verifier_proof_id' "$SAMPLES_DIR/sp1_program_id.json")

echo "  SP1 Verifier ID:       $SP1_VERIFIER_ID"
echo "  SP1 Aggregator ID:     $SP1_AGGREGATOR_ID"
echo "  SP1 Verifier Proof ID: $SP1_VERIFIER_PROOF_ID"
echo "  SP1 Verifier Address:  $SP1_ADDRESS"

# ZkCoProcessorType.Succinct = 2 (enum: Unknown=0, RiscZero=1, Succinct=2, Pico=3)
# setZkConfiguration(ZkCoProcessorType, (bytes32 verifierId, bytes32 aggregatorId, address zkVerifier), bytes32 verifierProofId)
cast send "$VERIFIER_ADDRESS" \
    "setZkConfiguration(uint8,(bytes32,bytes32,address),bytes32)" \
    2 \
    "($SP1_VERIFIER_ID,$SP1_AGGREGATOR_ID,$SP1_ADDRESS)" \
    "$SP1_VERIFIER_PROOF_ID" \
    --rpc-url "$RPC_URL" \
    --private-key "$PRIVATE_KEY"

echo "SP1 ZK configuration set."


# ============================================================
# Summary
# ============================================================
echo ""
echo "=== Done ==="
echo ""
echo "Deployed contracts:"
echo "  NitroEnclaveVerifier: $VERIFIER_ADDRESS"
echo "  SP1Verifier:          $SP1_ADDRESS"
echo ""

"
