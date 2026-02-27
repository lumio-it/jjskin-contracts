#!/usr/bin/env bash
# mutation-test.sh — Run Gambit mutation testing on JJSKIN.sol
#
# Usage: bash scripts/mutation-test.sh [--quick]
#   --quick  Stop after first 50 mutants (for rapid feedback)
#
# Prerequisites:
#   - gambit (https://github.com/Certora/gambit/releases)
#   - solc 0.8.31 (solc-select install 0.8.31 && solc-select use 0.8.31)
#   - forge (foundry)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Parse args
MAX_MUTANTS=0  # 0 = unlimited
if [[ "${1:-}" == "--quick" ]]; then
    MAX_MUTANTS=50
    echo "[*] Quick mode: testing first $MAX_MUTANTS mutants only"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check prerequisites
if ! command -v gambit &>/dev/null; then
    echo -e "${RED}ERROR: gambit not found. Install from https://github.com/Certora/gambit/releases${NC}"
    exit 1
fi

if ! command -v forge &>/dev/null; then
    echo -e "${RED}ERROR: forge not found. Install foundry.${NC}"
    exit 1
fi

echo "========================================"
echo "  JJSKIN Mutation Testing with Gambit"
echo "========================================"
echo ""

# Clean previous run
rm -rf gambit_out

# 1. Generate mutants
echo "[1/3] Generating mutants..."
gambit mutate --json gambit-conf.json 2>&1 | tail -5

MUTANT_COUNT=$(ls -d gambit_out/mutants/*/ 2>/dev/null | wc -l | tr -d ' ')
echo -e "  Generated ${YELLOW}${MUTANT_COUNT}${NC} mutants"
echo ""

if [[ "$MUTANT_COUNT" -eq 0 ]]; then
    echo -e "${RED}No mutants generated. Check gambit-conf.json.${NC}"
    exit 1
fi

# 2. Test each mutant
echo "[2/3] Testing mutants..."
echo ""

KILLED=0
SURVIVED=0
ERRORS=0
SURVIVORS=()
TESTED=0

# Backup original source
cp src/JJSKIN.sol src/JJSKIN.sol.bak

trap 'cp src/JJSKIN.sol.bak src/JJSKIN.sol; rm -f src/JJSKIN.sol.bak' EXIT

for mutant_dir in gambit_out/mutants/*/; do
    TESTED=$((TESTED + 1))

    if [[ "$MAX_MUTANTS" -gt 0 && "$TESTED" -gt "$MAX_MUTANTS" ]]; then
        echo ""
        echo -e "${YELLOW}Reached --quick limit of $MAX_MUTANTS mutants.${NC}"
        break
    fi

    mutant_id=$(basename "$mutant_dir")
    mutant_file="$mutant_dir/src/JJSKIN.sol"

    if [[ ! -f "$mutant_file" ]]; then
        ERRORS=$((ERRORS + 1))
        continue
    fi

    # Apply mutant
    cp "$mutant_file" src/JJSKIN.sol

    # Run tests (suppress output, fail-fast for speed)
    if forge test --fail-fast --no-match-contract "Invariant" 2>/dev/null 1>/dev/null; then
        SURVIVED=$((SURVIVED + 1))
        SURVIVORS+=("$mutant_id")
        printf "  Mutant %s: ${RED}SURVIVED${NC}\n" "$mutant_id"
    else
        KILLED=$((KILLED + 1))
        printf "  Mutant %s: ${GREEN}KILLED${NC}\n" "$mutant_id"
    fi

    # Restore original (trap handles final cleanup)
    cp src/JJSKIN.sol.bak src/JJSKIN.sol
done

# 3. Results
echo ""
echo "========================================"
echo "  MUTATION TESTING RESULTS"
echo "========================================"
echo ""
echo "  Total mutants tested: $TESTED"
echo -e "  ${GREEN}Killed:   $KILLED${NC}"
echo -e "  ${RED}Survived: $SURVIVED${NC}"
echo -e "  Errors:   $ERRORS"
echo ""

if [[ "$TESTED" -gt 0 ]]; then
    KILL_RATE=$(echo "scale=1; $KILLED * 100 / $TESTED" | bc)
    echo -e "  Kill rate: ${YELLOW}${KILL_RATE}%${NC}"

    if (( $(echo "$KILL_RATE >= 90" | bc -l) )); then
        echo -e "  ${GREEN}EXCELLENT: Strong test suite!${NC}"
    elif (( $(echo "$KILL_RATE >= 70" | bc -l) )); then
        echo -e "  ${YELLOW}GOOD: Some gaps to address.${NC}"
    else
        echo -e "  ${RED}NEEDS WORK: Significant test gaps.${NC}"
    fi
fi

# List surviving mutants
if [[ ${#SURVIVORS[@]} -gt 0 ]]; then
    echo ""
    echo "Surviving mutants (need targeted tests):"
    for sid in "${SURVIVORS[@]}"; do
        echo "  - gambit_out/mutants/$sid/"
        # Show the diff for each survivor
        diff_file="gambit_out/mutants/$sid/src/JJSKIN.sol"
        if [[ -f "$diff_file" ]]; then
            echo "    Diff:"
            diff src/JJSKIN.sol.bak "$diff_file" 2>/dev/null | head -20 | sed 's/^/    /'
            echo ""
        fi
    done
fi

echo ""
echo "Done. Full mutant details in gambit_out/mutants/"
