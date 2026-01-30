#!/usr/bin/env bash
# Storage Layout Check Script
#
# This script generates and compares storage layouts for upgradeable contracts.
# Used in CI to detect storage layout changes that could break upgrades.
#
# Usage:
#   ./scripts/storage-layout-check.sh          # Check layouts against snapshots
#   ./scripts/storage-layout-check.sh --update # Update snapshots with current layouts
#
# The script checks all upgradeable contracts and ensures their storage
# layouts haven't changed unexpectedly. Storage layout changes in upgradeable
# contracts can cause storage collisions and data corruption after upgrades.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SNAPSHOT_DIR="$ROOT_DIR/.storage-layouts"

UPGRADEABLE_CONTRACTS=(
    "EspressoTEEVerifier"
    "EspressoSGXTEEVerifier"
    "EspressoNitroTEEVerifier"
)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

generate_layout() {
    local contract=$1
    local output_file=$2
    
    log_info "Generating storage layout for $contract..."
    
    forge inspect "$contract" storage-layout --json > "$output_file"
}

compare_layouts() {
    local contract=$1
    local snapshot_file="$SNAPSHOT_DIR/${contract}.json"
    local current_file="$SNAPSHOT_DIR/${contract}.current.json"
    
    if [[ ! -f "$snapshot_file" ]]; then
        log_error "No snapshot found for $contract at $snapshot_file"
        log_error "Run with --update to create initial snapshots"
        return 1
    fi
    
    generate_layout "$contract" "$current_file"
    
    if diff -q "$snapshot_file" "$current_file" > /dev/null 2>&1; then
        log_info "$contract: Storage layout unchanged"
        rm -f "$current_file"
        return 0
    else
        log_error "$contract: Storage layout has CHANGED!"
        log_error ""
        log_error "This could break contract upgrades. Differences:"
        log_error "-------------------------------------------"
        diff --color=always "$snapshot_file" "$current_file" || true
        log_error "-------------------------------------------"
        log_error ""
        log_error "If this change is intentional:"
        log_error "  1. Ensure the change is backwards compatible"
        log_error "  2. Run: ./scripts/storage-layout-check.sh --update"
        log_error "  3. Commit the updated snapshot"
        rm -f "$current_file"
        return 1
    fi
}

update_snapshots() {
    log_info "Updating storage layout snapshots..."
    
    mkdir -p "$SNAPSHOT_DIR"
    
    log_info "Building contracts..."
    forge build --quiet
    
    for contract in "${UPGRADEABLE_CONTRACTS[@]}"; do
        generate_layout "$contract" "$SNAPSHOT_DIR/${contract}.json"
        log_info "Updated snapshot for $contract"
    done
    
    log_info "All snapshots updated successfully!"
    log_info "Don't forget to commit the changes in $SNAPSHOT_DIR"
}

check_layouts() {
    log_info "Checking storage layouts for upgradeable contracts..."
    log_info "Building contracts..."
    forge build --quiet
    
    local failed=0
    
    for contract in "${UPGRADEABLE_CONTRACTS[@]}"; do
        if ! compare_layouts "$contract"; then
            failed=1
        fi
    done
    
    if [[ $failed -eq 1 ]]; then
        log_error ""
        log_error "Storage layout check FAILED!"
        log_error "Review the changes above carefully before updating snapshots."
        exit 1
    fi
    
    log_info ""
    log_info "All storage layouts are compatible!"
}

main() {
    cd "$ROOT_DIR"
    
    if [[ "${1:-}" == "--update" ]]; then
        update_snapshots
    elif [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
        echo "Storage Layout Check Script"
        echo ""
        echo "Usage:"
        echo "  $0           Check layouts against snapshots (CI mode)"
        echo "  $0 --update  Update snapshots with current layouts"
        echo "  $0 --help    Show this help message"
        echo ""
        echo "Contracts checked:"
        for contract in "${UPGRADEABLE_CONTRACTS[@]}"; do
            echo "  - $contract"
        done
    else
        check_layouts
    fi
}

main "$@"
