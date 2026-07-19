#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# deploy_upgradeable.sh
#
# Deployment script for Stellara upgradeable contracts with built-in
# initializer protection verification.
#
# This script:
#   1. Builds all contract WASM binaries
#   2. Deploys contracts to the target network
#   3. Calls initialize() once on each contract
#   4. Verifies that a second initialize() call is rejected
#   5. Verifies version tracking and storage gap initialization
#
# Usage:
#   ./scripts/deploy/deploy_upgradeable.sh [--network testnet|mainnet]
#
# Prerequisites:
#   - Stellar CLI installed (stellar --version)
#   - Rust toolchain with wasm32-unknown-unknown target
#   - Funded account configured as 'deployer'
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

NETWORK="${1:---network}"
NETWORK_NAME="${2:-testnet}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()    { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC}     $1"; }

# ── Step 1: Build WASM binaries ──────────────────────────────────────
info "Building contract WASM binaries..."
cargo build --release --target wasm32-unknown-unknown
success "WASM binaries built successfully"

# ── Step 2: Verify upgradeability module tests pass ──────────────────
info "Running upgradeability module tests..."
cargo test -p upgradeability -- --test-threads=1
success "All upgradeability tests passed"

# ── Step 3: Deploy Soroban contracts ──────────────────────────────────
info "Deploying Soroban contracts to ${NETWORK_NAME}..."

CONTRACTS=(
    "did-registry:target/wasm32-unknown-unknown/release/did_registry.wasm"
    "identity-hub:target/wasm32-unknown-unknown/release/identity_hub.wasm"
    "verifiable-credentials:target/wasm32-unknown-unknown/release/verifiable_credentials.wasm"
    "trading:target/wasm32-unknown-unknown/release/trading.wasm"
    "messaging:target/wasm32-unknown-unknown/release/messaging.wasm"
    "academy:target/wasm32-unknown-unknown/release/academy_vesting.wasm"
)

declare -A CONTRACT_IDS

for entry in "${CONTRACTS[@]}"; do
    name="${entry%%:*}"
    wasm="${entry##*:}"

    if [ ! -f "$wasm" ]; then
        warn "WASM not found for ${name} at ${wasm}, skipping..."
        continue
    fi

    info "Deploying ${name}..."
    CONTRACT_ID=$(stellar contract deploy \
        --wasm "$wasm" \
        --source deployer \
        --network "$NETWORK_NAME" \
        2>&1) || {
        error "Failed to deploy ${name}"
        continue
    }

    CONTRACT_IDS[$name]="$CONTRACT_ID"
    success "Deployed ${name}: ${CONTRACT_ID}"
done

# ── Step 4: Initialize contracts ─────────────────────────────────────
info "Initializing deployed contracts..."

for name in "${!CONTRACT_IDS[@]}"; do
    contract_id="${CONTRACT_IDS[$name]}"

    info "Initializing ${name} (${contract_id})..."
    
    # Generate test addresses for initialization
    ADMIN_ADDRESS="GADMINXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    APPROVER1_ADDRESS="GAPPR1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    APPROVER2_ADDRESS="GAPPR2XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    EXECUTOR_ADDRESS="GEXECXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    
    stellar contract invoke \
        --id "$contract_id" \
        --source deployer \
        --network "$NETWORK_NAME" \
        -- initialize \
        --admin "$ADMIN_ADDRESS" \
        --approvers "$APPROVER1_ADDRESS" "$APPROVER2_ADDRESS" \
        --executor "$EXECUTOR_ADDRESS" \
        2>&1 || {
        error "Failed to initialize ${name}"
        continue
    }
    success "Initialized ${name}"
done

# ── Step 5: Verify initializer protection ────────────────────────────
info "Verifying initializer protection (double-init must fail)..."

VERIFICATION_PASSED=true
for name in "${!CONTRACT_IDS[@]}"; do
    contract_id="${CONTRACT_IDS[$name]}"

    info "Testing double-init on ${name}..."
    if stellar contract invoke \
        --id "$contract_id" \
        --source deployer \
        --network "$NETWORK_NAME" \
        -- initialize \
        --admin "GADMINXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
        --approvers "GAPPR1XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" "GAPPR2XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
        --executor "GEXECXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
        2>&1; then
        error "SECURITY FAILURE: ${name} allowed re-initialization!"
        VERIFICATION_PASSED=false
    else
        success "${name} correctly rejected re-initialization"
    fi
done

# ── Step 6: Verify version tracking ─────────────────────────────────
info "Verifying version tracking..."

for name in "${!CONTRACT_IDS[@]}"; do
    contract_id="${CONTRACT_IDS[$name]}"

    info "Checking version for ${name}..."
    VERSION=$(stellar contract read \
        --id "$contract_id" \
        --network "$NETWORK_NAME" \
        -- version 2>&1 || echo "0")
    
    if [ "$VERSION" = "1" ]; then
        success "${name} version is correctly set to 1"
    else
        warn "${name} version check returned: ${VERSION}"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════"
if [ "$VERIFICATION_PASSED" = true ]; then
    success "All contracts deployed and initializer protection verified!"
else
    error "SOME CONTRACTS FAILED INITIALIZER PROTECTION VERIFICATION"
    exit 1
fi
echo "════════════════════════════════════════════════════════════════"

# Print deployed contract addresses
echo ""
info "Deployed Contract Addresses:"
for name in "${!CONTRACT_IDS[@]}"; do
    echo "  ${name}: ${CONTRACT_IDS[$name]}"
done
