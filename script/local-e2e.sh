#!/bin/bash
set -euo pipefail

# ============================================================
# Local E2E Test for TEE Oracle Settlement
# ============================================================
# Flow: Extension → MPC-TLS (real Steam) → tlsn-server → settleByOracle → Anvil
#
# Prerequisites:
#   - foundry (anvil, forge, cast)
#   - docker
#   - tlsn-server Docker image built:
#     docker build -t tlsn-server /path/to/tlsn-server
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TLSN_SERVER_DIR="${TLSN_SERVER_DIR:-$HOME/Desktop/tlsn-server}"

# ── Anvil well-known keys ──
# Account #0 = deployer/buyer
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Account #1 = oracle
ORACLE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
# Account #2 = seller
SELLER_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"

# ── Trade parameters (edit these for your test) ──
SELLER_STEAM_ID="${SELLER_STEAM_ID:-76561198366018280}"
BUYER_STEAM_ID="${BUYER_STEAM_ID:-76561198404282737}"
ASSET_ID="${ASSET_ID:-40964044588}"
TRADE_OFFER_ID="${TRADE_OFFER_ID:-8653813160}"
PRICE_USDC="${PRICE_USDC:-10000000}" # 10 USDC

RPC_URL="http://localhost:8545"

# ── Colors ──
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }

cleanup() {
    log "Cleaning up..."
    [ -n "${ANVIL_PID:-}" ] && kill "$ANVIL_PID" 2>/dev/null || true
    docker rm -f tlsn-local 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================
# Step 1: Start Anvil
# ============================================================
log "Starting Anvil..."
anvil --host 0.0.0.0 --silent &
ANVIL_PID=$!
sleep 2

# Verify Anvil is up
if ! cast block-number --rpc-url "$RPC_URL" &>/dev/null; then
    err "Anvil failed to start"
    exit 1
fi
log "Anvil running (PID: $ANVIL_PID)"

# ============================================================
# Step 2: Deploy contracts via forge script
# ============================================================
log "Deploying contracts..."
cd "$PROJECT_DIR"

DEPLOYER_KEY="$DEPLOYER_KEY" \
ORACLE_KEY="$ORACLE_KEY" \
SELLER_KEY="$SELLER_KEY" \
SELLER_STEAM_ID="$SELLER_STEAM_ID" \
BUYER_STEAM_ID="$BUYER_STEAM_ID" \
ASSET_ID="$ASSET_ID" \
TRADE_OFFER_ID="$TRADE_OFFER_ID" \
PRICE_USDC="$PRICE_USDC" \
forge script script/DeployLocal.s.sol:DeployLocal \
    --broadcast \
    --rpc-url "$RPC_URL" \
    -vvv 2>&1 | tee /tmp/deploy-local.log

# Extract addresses from forge output
MARKETPLACE=$(grep "MARKETPLACE" /tmp/deploy-local.log | head -1 | awk '{print $NF}')
FACTORY=$(grep "FACTORY" /tmp/deploy-local.log | head -1 | awk '{print $NF}')
if [ -z "$MARKETPLACE" ]; then
    err "Failed to extract marketplace address from deploy output"
    err "Check /tmp/deploy-local.log for details"
    exit 1
fi
if [ -z "$FACTORY" ]; then
    err "Failed to extract factory address from deploy output"
    exit 1
fi
log "Marketplace deployed at: $MARKETPLACE"
log "Factory deployed at: $FACTORY"

# ============================================================
# Step 3: Verify on-chain state
# ============================================================
log "Verifying deployment..."

# Check oracle is set
ORACLE_ADDR=$(cast call "$MARKETPLACE" "oracle()(address)" --rpc-url "$RPC_URL")
log "  Oracle: $ORACLE_ADDR"

# Check purchase exists and is Active (status = 0)
PURCHASE=$(cast call "$MARKETPLACE" "purchases(uint64)(address,uint40,uint8,uint48)" "$ASSET_ID" --rpc-url "$RPC_URL")
log "  Purchase: $PURCHASE"

# Check escrow commitment exists
COMMITMENT=$(cast call "$MARKETPLACE" "escrowCommitment(uint64)(bytes32)" "$ASSET_ID" --rpc-url "$RPC_URL")
log "  Commitment: $COMMITMENT"

if [ "$COMMITMENT" = "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
    err "Escrow commitment is zero — commitTradeOffer may have failed"
    exit 1
fi
log "On-chain state verified!"

# ============================================================
# Step 4: Update oracle config with marketplace address
# ============================================================
log "Updating local-oracle.yaml with deployed addresses..."
# Replace placeholders with actual addresses (two separate patterns for the two fields)
sed -i.bak \
    -e "s|contract_address: \"FILL_AFTER_DEPLOY\"|contract_address: \"$MARKETPLACE\"|" \
    -e "s|steam_factory_address: \"FILL_AFTER_DEPLOY\"|steam_factory_address: \"$FACTORY\"|" \
    "$SCRIPT_DIR/local-oracle.yaml"
rm -f "$SCRIPT_DIR/local-oracle.yaml.bak"

# ============================================================
# Step 5: Build + run tlsn-server (optional)
# ============================================================
if [ -d "$TLSN_SERVER_DIR" ]; then
    log "Building tlsn-server Docker image..."
    docker build -t tlsn-server "$TLSN_SERVER_DIR"

    # Strip 0x prefix for the env var
    ORACLE_KEY_HEX="${ORACLE_KEY#0x}"

    log "Starting tlsn-server..."
    docker run -d \
        --name tlsn-local \
        -p 7047:7047 \
        -v "$SCRIPT_DIR/local-oracle.yaml:/app/config.yaml" \
        -e "ORACLE_SIGNING_KEY=$ORACLE_KEY_HEX" \
        --add-host=host.docker.internal:host-gateway \
        tlsn-server --config /app/config.yaml

    sleep 3

    # Health check
    if curl -sf http://localhost:7047/health &>/dev/null; then
        log "tlsn-server running on :7047"
    else
        warn "tlsn-server may not be ready yet. Check: docker logs tlsn-local"
    fi
else
    warn "tlsn-server not found at $TLSN_SERVER_DIR — skipping Docker build"
    warn "Set TLSN_SERVER_DIR env var or build manually"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "========================================"
echo "  Local E2E Environment Ready"
echo "========================================"
echo "  Anvil RPC      : $RPC_URL"
echo "  Marketplace    : $MARKETPLACE"
echo "  Asset ID       : $ASSET_ID"
echo "  Trade Offer ID : $TRADE_OFFER_ID"
echo "  Notary Server  : http://localhost:7047"
echo ""
echo "  Extension config:"
echo "    VITE_NOTARY_URL=http://localhost:7047"
echo ""
echo "  Verification commands:"
echo "    cast call $MARKETPLACE 'oracle()(address)' --rpc-url $RPC_URL"
echo "    cast call $MARKETPLACE 'purchases(uint64)(address,uint40,uint8,uint48)' $ASSET_ID --rpc-url $RPC_URL"
echo "    cast call $MARKETPLACE 'escrowCommitment(uint64)(bytes32)' $ASSET_ID --rpc-url $RPC_URL"
echo ""
echo "  After settlement:"
echo "    cast call $MARKETPLACE 'purchases(uint64)(address,uint40,uint8,uint48)' $ASSET_ID --rpc-url $RPC_URL"
echo "    # Status 1=Released, 2=Refunded"
echo "========================================"
echo ""
log "Press Ctrl+C to stop Anvil and tlsn-server"

# Keep running until interrupted
wait "$ANVIL_PID"
