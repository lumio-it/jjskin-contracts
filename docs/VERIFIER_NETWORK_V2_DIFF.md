# VerifierNetwork V2 - Complete Implementation Diff (FINAL CORRECTED V3.3.6)

This document contains the **fully corrected** code changes for implementing stake-weighted self-selection with:

**Core Security Features:**
- Selection-only bucket snapshots (prevents grinding)
- Single pending epoch gating (prevents DoS)
- **O(1) VRF callback with chunked finalization** (prevents gas limit revert)
- **Forced change snapshot updates** (slash/suspend update selection state)
- **Liveness count checks** (`bucketCountSel[]` ensures QUORUM eligible)
- **Dynamic τ for retries** (compensates for excluded prior participants)
- **Unbonded stake slashable until claim** (snapshot never exceeds slashable)
- One participation per batch (prevents slashing bugs)
- **Rebuild-only pause** (V3.3.4: narrow pause to actual rebuild, not all of pendingEpoch)
- **Stake freeze after seed reveal** (prevents grinding via late mutations)
- **Epoch-bound batches** (old-epoch batches fail on retry after transition)
- **Epoch timeout escape hatch** (prevents permissionless DoS)
- **Snapshot rebuild safety** (defer forced changes during rebuild)
- **uint16 vote counters** (prevents overflow on tail cases)
- **Cancellation safety** (V3.1: block cancel after VRF fulfilled)
- **Anti-grinding seed** (V3.2: blockhash mix-in prevents batchId committee grinding)
- **Effective min stake** (V3.2: bucket-snapped threshold for consistency)
- **Batch nonce collision guard** (V3.2: prevents batchId overwrites)
- **256-bit roll precision** (V3.3: mulDiv for overflow-safe threshold calc)
- **Explicit slashNoReveal** (V3.2: enforceable commit-no-reveal slashing)
- **Finalization incentives** (V3.3: pull pattern + count guard prevents drain)
- **Stored entropy at creation** (V3.3: createdEntropy avoids 256-block limit)
- **Rebuild-safe forced changes** (V3.3: defer or apply to Next arrays)
- **Epoch rate limiting** (V3.3: EPOCH_MIN_INTERVAL cooldown)
- **SelectionStake clamp on claim** (V3.3.1: preserves "snapshot ≤ slashable" invariant)
- **Open-ended last bucket** (V3.3.2: bucket 13 covers [8.192M, ∞), fixes array bounds)
- **Batch value ceiling** (V3.3.2: MAX_BATCH_VALUE prevents minStake exceeding bucket model)
- **Auto-finalize for small sets** (V3.3.2: inline finalize in VRF callback when ≤50 verifiers)
- **Rebuild-safe slashing via deltas** (V3.3.3: selectionEpochTag + Next delta corrections)
- **Per-round reveal deadlines** (V3.3.3: roundRevealDeadline prevents stale deadline slashing)
- **MinStake out-of-range guard** (V3.3.3: explicit revert instead of silent clamp)
- **Epoch nonce prevents ID reuse** (V3.3.4: monotonic epochNonce + vrfRequestId check)
- **Overflow-safe selection numerator** (V3.3.3: check stake*tau < 2^128)
- **Fulfilled-no-progress escape** (V3.3.4: cancel if VRF fulfilled but rebuild not started)
- **Concentration cap for liveness** (V3.3.4: max stake share ≤ 1/τ_max prevents saturation)
- **Deferred suspension completion** (V3.3.4: needsSuspension + processSuspension path)
- **Audit batch entropy + nonce** (V3.3.4: createdEntropy and collision guard for audits)
- **Proportional finalization reward** (V3.3.4: reward × processed / CHUNK_SIZE)
- **Seed-agnostic readiness** (V3.3.4: use fulfilled flag, not randomSeed != 0)
- **Epoch-starter bond** (V3.3.5: bond required to call startNewEpoch, returned on finalization)
- **Stale epoch commit rejection** (V3.3.5: submitCommit reverts if batchEpoch != activeEpoch)
- **VRF-fulfilled batch pause** (V3.3.5: block batch creation when VRF fulfilled but not finalized)
- **Pure O(1) VRF callback** (V3.3.5: removed auto-finalize, callback just stores seed)
- **Bucket-aware concentration cap** (V3.3.5: per-bucket max stake instead of global percentage)
- **Corrected τ_max math** (V3.3.5: τ_max = 11 for MAX_ROUNDS=3, not 13)
- **Single-bucket concentration check** (V3.3.6: check only tightest tier, not all higher buckets)
- **Deferred suspension flag fix** (V3.3.6: actually set needsSuspension in _slashVerifier)
- **Rebuild-start griefing protection** (V3.3.6: only epochStarter can start first chunk)
- **Continuous concentration enforcement** (V3.3.6: check concentration cap at epoch finalization)
- **submitReveal reentrancy guard** (V3.3.6: nonReentrant modifier added)

**Gas Optimizations (V3.1):**
- **Memory accumulators in finalizeEpochChunk()** - reduces ~200 SSTORE to ~30 per chunk
- **O(1) eligibility lookups** - suffix sum caches instead of O(14) loop
- **Bit-scan _getBucket()** - binary search instead of while loop
- **unchecked increments** - safe gas savings in bounded loops

## Critical Safety Invariants

### Epoch Transition Pause (Narrowed in V3.3.4, Refined in V3.3.5)
**V3.3.4 FIX**: The original pause (`pendingEpoch != 0`) was too broad. Batches/commits were blocked even when VRF hasn't arrived yet, creating unnecessary downtime.

**V3.3.5 REFINEMENT**: The V3.3.4 "rebuild-only" pause was too narrow for batch creation. Once VRF is fulfilled, the seed is public. Allowing batch creation during this window enables grinding: a batch creator can influence `batchId` to prefer a colluding committee (since seed is known, selection is deterministic).

**New rules (V3.3.5)**:
- `createBatchFromArweave()` reverts if VRF fulfilled but not finalized (`_isStakeFrozen()`) - **changed from V3.3.4**
- `submitCommit()` reverts only during rebuild (`_isSnapshotRebuilding()`) - **unchanged from V3.3.4**
- `submitCommit()` also reverts if `batchEpoch != activeEpoch` (stale epoch) - **new in V3.3.5**
- Before VRF arrives: batch creation proceeds normally
- After VRF fulfilled but before rebuild: commits OK for existing batches, but NO new batches
- Existing batches in REVEAL_PHASE can always reveal

**Rationale**: The VRF-fulfilled window is dangerous for batch creation (grinding), but safe for commits on existing batches (batchId already fixed). The stale epoch check prevents commits on batches from old epochs whose snapshot was overwritten.

This ensures the single snapshot is never read while being overwritten.

**V3.3.4 UPDATE - COMMIT_PHASE Batch Impact**:
~~Batches in COMMIT_PHASE during epoch transition are effectively "killed"~~ (V3.3.1-3 behavior).
With V3.3.4's narrowed pause, batches can collect commits until rebuild starts. After rebuild:
- If `batchEpoch == activeEpoch`: They can retry with the new snapshot (but verifier selection changes)
- If `batchEpoch != activeEpoch` (stale epoch): They fail permanently on retry (`_openNextRoundOrFail`)

**Mitigation**: The protocol assumes:
1. Epoch transitions are infrequent (every few hours at most, gated by `EPOCH_MIN_INTERVAL`)
2. Finalization is fast (permissionless, incentivized via `FINALIZE_CHUNK_REWARD`)
3. Most batches complete within a single epoch

If transition duration is a concern, operators should avoid starting new epochs when many batches
are in COMMIT_PHASE. This is a design trade-off for single-snapshot simplicity.

### Epoch-Bound Batches (Single Snapshot Consequence)
Since we use a single snapshot that gets overwritten on epoch transition:
- After transition completes, batches with `batchEpoch != activeEpoch` **cannot retry**
- `_openNextRoundOrFail()` auto-fails stale-epoch batches
- Batches in REVEAL_PHASE at transition time can finish if they reach consensus
- This is the trade-off for avoiding double-buffer complexity

### Epoch Timeout Escape Hatch (Expanded in V3.3.4)
To prevent permissionless DoS via `startNewEpoch()`:
- `EPOCH_VRF_TIMEOUT = 1 hours` after VRF request
- If VRF not fulfilled within timeout, `cancelStaleEpoch()` clears `pendingEpoch`
- **V3.3.4 FIX**: Added `EPOCH_FINALIZE_TIMEOUT` escape hatch (see below)

**V3.3.4 ADDITION - Fulfilled-but-no-progress escape**:
Previously, once VRF was fulfilled, there was no cancel path. But if VRF arrives and *nobody* starts finalization, the system is stuck. New escape hatch:
- `EPOCH_FINALIZE_TIMEOUT = 6 hours` after VRF fulfillment
- Cancel allowed if `epoch.fulfilled == true` AND `epochFinalizedUpTo[epoch] == 0`
- Once rebuild starts (`epochFinalizedUpTo > 0`), cancel is blocked forever
- This handles the "VRF arrived but no keeper finalized" edge case

**Rate limiting via `EPOCH_MIN_INTERVAL`**:
- Cannot call `startNewEpoch()` within 4 hours of previous epoch start
- Prevents epoch-spam DoS while still allowing protocol progress

### Cancellation Safety (Expanded in V3.3.4)
~~The V3 design had a bug where cancelling an epoch after rebuild started would corrupt selection stakes.~~

**Current rules for `cancelStaleEpoch()`**:
1. `epochFinalizedUpTo[pendingEpoch] > 0` (rebuild started) → **ALWAYS REVERT** (would corrupt snapshot)
2. `epoch.fulfilled == false` AND `elapsed > EPOCH_VRF_TIMEOUT` → **CANCEL OK** (VRF never arrived)
3. `epoch.fulfilled == true` AND `epochFinalizedUpTo == 0` AND `elapsed > EPOCH_FINALIZE_TIMEOUT` → **CANCEL OK** (V3.3.4: VRF arrived but no one finalized)

**V3.3.4 FIX - Epoch ID reuse prevention**:
After cancel, `vrfRequestToEpoch[requestId]` still maps to the cancelled epoch. A late VRF fulfillment could match!
- Add `epochNonce` monotonic counter, use in epoch ID generation
- Store `epochs[epoch].vrfRequestId = requestId` at epoch creation
- In `fulfillRandomWords`: check `epochs[epoch].vrfRequestId == requestId`
- After cancel: delete `vrfRequestToEpoch[requestId]` mapping

### Anti-Grinding Seed (Fixed in V3.2, refined in V3.3)
~~V3.1 had a grinding vector: once `activeEpoch` is finalized, `epoch.randomSeed` is public. A batch creator choosing which assets to bundle could influence `batchId` to prefer a colluding committee.~~

**Fix applied (V3.2)**: Per-round seed mixes in block entropy.

**Refinement (V3.3)**: `blockhash(n)` returns 0 after 256 blocks. If batch creation → selection takes >256 blocks, grinding becomes possible again. Solution: **store entropy at batch creation time** as `createdEntropy`:
```solidity
// In createBatchFromArweave:
batch.createdEntropy = bytes32(block.prevrandao);  // Stored at creation, never stale

// In _isSelected:
bytes32 roundSeed = keccak256(abi.encode(epoch.randomSeed, batchId, round, batch.createdEntropy));
```

This kills offline grinding AND avoids the 256-block staleness issue.

### Effective Min Stake (Fixed in V3.2)
~~V3.1 had inconsistent eligibility checks: per-verifier used exact `stake >= minStake`, but denominator used bucket-rounded `eligibleStakeFromBucket[_getMinBucket(minStake)]`.~~

**Fix applied**: Use "effective min stake" snapped to bucket boundary everywhere:
```solidity
uint256 minStakeRaw = _getMinStake(batch.totalValue);
uint8 minBucket = _getMinBucket(minStakeRaw);
uint256 minStakeEff = _getBucketLowerBound(minBucket);  // Bucket-snapped

// BOTH checks use minStakeEff:
if (stake < minStakeEff) return false;
uint256 eligibleStake = eligibleStakeFromBucket[minBucket];
```

This is conservative (higher min stake than formula) but ensures selection probabilities are consistent.

### Batch Nonce Collision Guard (Fixed in V3.2)
~~V3.1 had collision risk: same sender, same params, same block could produce duplicate `batchId`, overwriting state.~~

**Fix applied**: Add monotonic nonce + collision check:
```solidity
uint256 public batchNonce;  // New storage variable

// In createBatchFromArweave:
batchId = keccak256(abi.encode(assetIds, arweaveBlock, block.number, msg.sender, batchNonce++));
if (batches[batchId].createdAt != 0) revert BatchIdCollision();
```

### 256-bit Roll Precision (Fixed in V3.2, overflow fix in V3.3)
~~V3.1 used `roll = hash % BPS` (10,000 outcomes), causing quantization issues where small stakes could round threshold to 0.~~

**Fix applied (V3.2)**: Use full 256-bit precision.

**CRITICAL BUG (V3.2)**: The naive calculation `(stake * tau * type(uint256).max) / eligibleStake` overflows in the numerator (`stake * tau * 2^256-1` wraps).

**Fix applied (V3.3)**: Use OpenZeppelin `Math.mulDiv` for 512-bit intermediate:
```solidity
// V3.2 (BROKEN - overflows):
// threshold = (numerator * type(uint256).max) / eligibleStake;

// V3.3 (CORRECT):
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

uint256 roll = uint256(keccak256(abi.encode(roundSeed, verifier)));
uint256 numerator = stake * tau;  // Safe for reasonable stakes (< 2^128)

if (numerator >= eligibleStake) return true;  // ≥100% selected

// mulDiv(a, b, c) computes (a * b) / c with 512-bit intermediate
uint256 threshold = Math.mulDiv(numerator, type(uint256).max, eligibleStake);
return roll < threshold;
```

This gives ~2^256 outcomes instead of 10,000, AND avoids overflow.

### Explicit slashNoReveal (Fixed in V3.2)
~~V3.1 had commit-no-reveal slashing "on paper" but no concrete enforcement path.~~

**Fix applied**: Add permissionless `slashNoReveal(batchId, verifier)` with onchain proof checks.

### Finalization Incentives (Fixed in V3.2, secured in V3.3)
~~V3.1 relied on altruistic keepers to call `finalizeEpochChunk()` - system could stall if nobody paid gas.~~

**Fix applied (V3.2)**: Pay small reward from protocol fees/slashing treasury per chunk finalized.

**CRITICAL BUG (V3.2)**: Calling `finalizeEpochChunk(count=0)` paid reward without making progress - infinite drain.

**Fix applied (V3.3)**:
1. **Guard**: `require(count > 0)` at function start
2. **Progress check**: Only pay reward if `end > start` (actual progress made)
3. **Pull pattern**: Accumulate rewards in `finalizerRewards[msg.sender]`, withdraw via separate `claimFinalizerRewards()`
4. **Reentrancy**: `nonReentrant` modifier added (external USDC transfer)

```solidity
// V3.3: Safe finalization reward pattern (updated V3.3.4: proportional)
mapping(address => uint256) public finalizerRewards;

function finalizeEpochChunk(uint256 epochId, uint256 count) external nonReentrant {
    if (count == 0) revert InvalidInput();
    // ... processing ...
    // V3.3.4 FIX: Proportional reward prevents "mining" with count=1
    uint256 processed = end - start;
    uint256 proratedReward = (FINALIZE_CHUNK_REWARD * processed) / EPOCH_FINALIZE_CHUNK_SIZE;
    if (proratedReward > 0 && slashingTreasury >= proratedReward) {
        slashingTreasury -= proratedReward;
        finalizerRewards[msg.sender] += proratedReward;  // Pull pattern
    }
}

function claimFinalizerRewards() external nonReentrant {
    uint256 amount = finalizerRewards[msg.sender];
    if (amount == 0) revert NoRewardsToClaim();
    finalizerRewards[msg.sender] = 0;
    usdc.safeTransfer(msg.sender, amount);
}
```

### Stake Freeze After Seed Reveal
When `pendingEpoch != 0 && epochs[pendingEpoch].fulfilled == true`:
- `registerVerifier()` reverts
- `addStake()` reverts
- `initiateUnbonding()` reverts
- `cancelUnbonding()` reverts
- `claimUnbonding()` reverts

This prevents grinding via stake mutations after seeing the VRF seed but before snapshot.

### Stake Concentration Cap (V3.3.4, Bucket-Aware in V3.3.5)
**PROBLEM**: With stake-weighted sortition, a verifier's selection probability is `p = (stake × τ) / eligibleStake`. If a whale has stake ≥ eligibleStake/τ, their probability exceeds 100% - they're always selected, breaking the random committee assumption.

**V3.3.4 APPROACH** (superseded): Global `MAX_STAKE_SHARE_BPS = 700` (7%) cap on total selection stake.

**V3.3.5 FIX - BUCKET-AWARE CAP**: The V3.3.4 global percentage approach was insufficient. Selection probability depends on `eligibleStake` at a specific `minBucket`, not total stake. A whale could be fine globally but dominate batches at certain value thresholds.

**New approach (V3.3.5)**:
```solidity
// For each bucket b from minBucket onwards, enforce:
// verifier_stake <= eligibleStakeFromBucket[b] / (τ_max * CONCENTRATION_FACTOR)
// where τ_max = 11 (MAX_ROUNDS=3, 0-indexed: 7 + 2*2 = 11)
// and CONCENTRATION_FACTOR = 2 (50% margin for safety)

uint256 public constant TAU_MAX = 11; // EXPECTED_COMMITTEE_SIZE + (MAX_ROUNDS-1) * TAU_ROUND_INCREMENT
uint256 public constant CONCENTRATION_FACTOR = 2; // 2x safety margin

function _checkConcentration(address verifier, uint256 newStake) internal view {
    if (activeVerifierCount < CONCENTRATION_ENFORCEMENT_MIN) return; // Bootstrap exception

    // V3.3.6 FIX: Check only the tightest tier (bucket k), not k..MAX_BUCKETS-1
    // Rationale: A verifier with stake in bucket k is eligible for batches with minBucket <= k.
    // The tightest constraint is bucket k itself (smallest eligible pool).
    // Higher buckets have LARGER eligible pools, so if k passes, all higher buckets pass.
    // The V3.3.5 loop was backwards: checking larger pools that are automatically satisfied.
    uint8 k = _getBucket(newStake);
    uint256 eligible = eligibleStakeFromBucket[k];
    if (eligible == 0) return; // No eligible stake in this tier

    uint256 maxAllowed = eligible / (TAU_MAX * CONCENTRATION_FACTOR);
    if (newStake > maxAllowed) revert StakeExceedsMax(newStake, maxAllowed);
}
```

**Rationale**: τ_max = 7 + 2×2 = 11 (not 13!) because MAX_ROUNDS=3 means rounds 0,1,2 (0-indexed). The concentration check ensures no verifier can have >50% selection probability at any eligibility tier.

**V3.3.6 FIX - SINGLE-BUCKET CHECK**: The V3.3.5 loop `for (b = bucket; b < MAX_BUCKETS)` was backwards! A verifier in bucket k is eligible for batches where `minBucket <= k`, meaning they participate in the pools for buckets 0, 1, ..., k (smaller batches), NOT k, k+1, ..., MAX_BUCKETS-1 (larger batches). The constraint is tightest at bucket k (smallest eligible pool). Higher buckets have larger pools, so if the check passes at bucket k, it passes everywhere. The fix checks only bucket k.

**Note**: This is more restrictive than the V3.3.4 global cap, but correctly prevents the "always selected for high-value batches" attack vector.

### Snapshot Rebuild Safety (Hardened in V3.3, Fixed in V3.3.3)
During chunked finalization (`epochFinalizedUpTo[pendingEpoch] > 0`):
- Forced changes (slash/suspend) now use **selectionEpochTag + delta corrections**
- `stakedAmount` and `selectionStake` are both updated correctly
- Next arrays receive delta corrections for already-processed verifiers
- This prevents underflow/double-count during partial rebuild

**CRITICAL BUG (V3.3)**: The V3.3 fix of blocking all forced changes during rebuild breaks:
- `slashNoReveal()` - cannot punish commit-no-reveal if reveal deadline falls during rebuild
- `_slashMinorityVoters()` - cannot slash minority voters during reveal/execute phase
- `_suspendVerifier()` - cannot suspend due to stake below MIN_STAKE

**PROBLEM**: If epoch rebuild takes longer than reveal window (permissionless, unbounded), verifiers can exploit the "slashing holiday" to commit-no-reveal without punishment.

**Fix applied (V3.3.3)**: Use `selectionEpochTag` to track processed verifiers and apply delta corrections:

1. **Track which verifiers were snapshotted in this epoch**: `selectionEpochTag[verifier] = epochId` when processed by `finalizeEpochChunk()`.

2. **Slashing during rebuild**: If `selectionEpochTag[verifier] == pendingEpoch`, the verifier was already processed into Next arrays. Apply delta correction to Next arrays (subtract old stake, add new stake).

3. **Suspension during rebuild**: Suspension still reverts during rebuild (swap-pop breaks iteration). But slashing is the critical path - suspension is rare.

```solidity
// V3.3.3: Track processed verifiers for delta corrections
mapping(address => uint256) internal selectionEpochTag;

// In finalizeEpochChunk():
verifier.selectionStake = stake;
selectionEpochTag[v] = epochId;  // Mark as processed for this epoch

// In _slashVerifier():
if (_isSnapshotRebuilding() && selectionEpochTag[verifierAddr] == pendingEpoch) {
    // Verifier already processed into Next - apply delta correction
    _applyNextSnapshotDelta(oldSelectionStake, newSelectionStake);
}
```

**Impact**: Slashing is now safe during rebuild. Suspension still blocked (rare operation, acceptable delay).

### Slashing Limitation (By Design)
With self-selection, we **cannot** punish "silent selected verifiers" (those who were selected but didn't commit) without O(n) iteration or adding proofs. The only enforceable slashing is:
- **Commit-no-reveal**: Committed but failed to reveal
- **Minority vote**: Revealed but voted against consensus

This is acceptable because the economic incentive (rewards) already encourages participation.

## Design Decisions

| Issue | Solution |
|-------|----------|
| VRF callback gas limit | O(1) callback, chunked `finalizeEpochChunk()` |
| Forced stake changes | Slash/suspend update `selectionStake` and buckets |
| Liveness guarantee | `bucketCountSel[]` for `eligibleCount >= QUORUM` check |
| Retry liveness | Dynamic τ: `τ_round = τ + round * 2` |
| Unbonding model | Stake stays slashable until `claimUnbonding()` |
| Grinding via live buckets | Selection-only buckets, updated at epoch finalization |
| Epoch DoS | Single pending epoch gating |
| Bucket/stake mismatch | BUCKET_BASE = MIN_STAKE (1000e6) |
| Retry overwrites votes | One participation per batch |
| Wasted reveal window | Early READY on 0 commits |
| Cap formula | V_max = totalSelectionStake / 1.5 |
| Buffer translation | τ=7 > QUORUM=5 (inherent buffer) |
| **Snapshot corruption** | Epoch transition pause (block batch/commit) |
| **Post-seed grinding** | Stake freeze after VRF fulfillment |
| **Silent verifier slashing** | Not enforceable (by design) |
| **Old-epoch batch retry** | Fail batches where `batchEpoch != activeEpoch` |
| **Epoch DoS** | Timeout escape hatch (`cancelStaleEpoch()`) |
| **Rebuild underflow/double-count** | Skip snapshot mutation during rebuild |
| **Vote counter overflow** | Use uint16 for all vote counters |
| **Finalize gas cost** | Memory accumulators (30 SSTORE vs 200+) |
| **Eligibility lookup gas** | Suffix sum caches (O(1) vs O(14)) |
| **Bucket calc gas** | Bit-scan MSB (O(4) vs O(14)) |
| **Cancel after VRF** | Block cancel once fulfilled (V3.1 fix) |
| **batchId committee grinding** | Store `createdEntropy` at batch creation (V3.3 fix) |
| **Eligibility bucket rounding** | Use effective minStake snapped to bucket boundary (V3.2 fix) |
| **batchId collision** | Monotonic nonce + collision check (V3.2 fix) |
| **Roll quantization** | Math.mulDiv for 512-bit precision (V3.3 fix) |
| **Commit-no-reveal enforcement** | Explicit `slashNoReveal()` function (V3.2 fix) |
| **Finalization liveness** | Pull pattern + count guard (V3.3 fix) |
| **Finalization reentrancy** | nonReentrant + pull pattern (V3.3 fix) |
| **Rebuild swap-pop corruption** | Block suspension during rebuild (V3.3 fix) |
| **Slashing during rebuild** | Delta corrections via selectionEpochTag (V3.3.3 fix) |
| **Epoch spam DoS** | EPOCH_MIN_INTERVAL rate limit (V3.3 fix) |
| **EPOCH_FINALIZE_TIMEOUT contradiction** | Removed - no cancel after VRF (V3.3 fix) |
| **claimUnbonding() breaks invariant** | Clamp selectionStake after stakedAmount reduction (V3.3.1 fix) |
| **minBucket==MAX_BUCKETS array OOB** | Open-ended last bucket [8.192M, ∞), never return 14 (V3.3.2 fix) |
| **Batch value exceeds bucket model** | MAX_BATCH_VALUE cap ensures minStake stays reasonable (V3.3.2 fix) |
| **Finalization liveness hole** | ~~Auto-finalize in VRF callback~~ → Epoch-starter bond (V3.3.5 fix) |
| **slashNoReveal stale deadline** | Per-round roundRevealDeadline tracking (V3.3.3 fix) |
| **MinStake silent clamp danger** | Explicit MinStakeOutOfRange revert (V3.3.3 fix) |
| **fulfillRandomWords epoch==0** | Reject epoch 0 as defense-in-depth (V3.3.3 fix) |
| **stake*tau overflow risk** | Overflow check with safe failure mode (V3.3.3 fix) |
| **Epoch ID reuse after cancel** | epochNonce + vrfRequestId check in callback (V3.3.4 fix) |
| **Pause window too broad** | Narrow to rebuild-only (`_isSnapshotRebuilding()`) (V3.3.4 fix) |
| **VRF fulfilled but no finalization** | EPOCH_FINALIZE_TIMEOUT escape hatch (V3.3.4 fix) |
| **Audit batch no createdEntropy** | Store createdEntropy + auditBatchNonce (V3.3.4 fix) |
| **Suspension blocked during rebuild** | Deferred suspension via `needsSuspension` + `processSuspension()` (V3.3.4 fix) |
| **Stake concentration saturation** | ~~Global 7% cap~~ → Bucket-aware cap: τ_max × CONCENTRATION_FACTOR (V3.3.5 fix) |
| **randomSeed==0 falsely invalid** | Use `epoch.fulfilled` flag, not seed value (V3.3.4 fix) |
| **Finalization reward mining** | Proportional reward: `reward × processed / CHUNK_SIZE` (V3.3.4 fix) |
| **VRF subscription drain** | Epoch-starter bond (10 USDC) + slash on cancel (V3.3.5 fix) |
| **Stale epoch commits accepted** | submitCommit checks `batchEpoch == activeEpoch` (V3.3.5 fix) |
| **Batch creation grinding** | Block batch creation when `_isStakeFrozen()` (V3.3.5 fix) |
| **Auto-finalize callback risk** | Removed - callback is pure O(1), bond incentivizes finalization (V3.3.5 fix) |
| **τ_max calculation error** | τ_max = 7 + (MAX_ROUNDS-1)*2 = 11, not 7+3*2=13 (V3.3.5 fix) |
| **Retrospective audit internal call** | Removed risky address(this).call pattern (V3.3.5 fix) |
| **Concentration cap loop backwards** | Check only tightest tier (bucket k), not k..MAX_BUCKETS-1 (V3.3.6 fix) |
| **Deferred suspension flag missing** | Set `needsSuspension[v] = true` in `_slashVerifier()` (V3.3.6 fix) |
| **Rebuild-start griefing** | Only epochStarter can call first `finalizeEpochChunk()` chunk (V3.3.6 fix) |
| **Concentration cap not continuous** | Check and cap at epoch finalization via `_checkContinuousConcentration()` (V3.3.6 fix) |
| **submitReveal reentrancy risk** | Added `nonReentrant` modifier (calls external JJSKIN) (V3.3.6 fix) |
| **StaleEpochBatch error duplicate** | Removed duplicate definition, unified to 3-param version (V3.3.6 fix) |

---

## Part 1: New Constants (VerifierNetwork.sol)

Add after existing constants (around line 250):

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// SELF-SELECTION PARAMETERS (stake-weighted public lottery)
// NOTE: Unlike true Algorand sortition, selection is publicly verifiable
// (all inputs are on-chain). This trades DoS resistance for simplicity.
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Base expected committee size (τ) - increases with retry round
/// @dev τ=7 with QUORUM=5 gives ~99.7% liveness at 90% participation
uint256 public constant EXPECTED_COMMITTEE_SIZE = 7;

/// @notice τ increment per retry round (compensates for excluded prior participants)
/// @dev τ_round = EXPECTED_COMMITTEE_SIZE + (round * TAU_ROUND_INCREMENT)
uint256 public constant TAU_ROUND_INCREMENT = 2;

/// @notice Quorum required for consensus (must be < τ)
uint256 public constant QUORUM = 5;

/// @notice Maximum retry rounds before batch fails
uint256 public constant MAX_ROUNDS = 3;

/// @notice Number of stake buckets (log₂ scale from MIN_STAKE)
/// @dev 14 buckets: MIN_STAKE × 2^i, covers $1K to $16M
uint256 public constant MAX_BUCKETS = 14;

/// @notice Bucket base equals MIN_STAKE for aligned boundaries
uint256 public constant BUCKET_BASE = MIN_STAKE; // 1000e6

/// @notice Safety margin for cryptoeconomic security (α = 1.5 = 15000 BPS)
/// @dev min_stake = α × V / (QUORUM × slash_rate)
uint256 public constant SECURITY_MARGIN_BPS = 15000;

/// @notice Chunk size for epoch finalization (gas-safe iteration)
/// @dev ~50 verifiers per chunk keeps gas well under block limit
uint256 public constant EPOCH_FINALIZE_CHUNK_SIZE = 50;

/// @notice Timeout for VRF fulfillment before epoch can be cancelled
/// @dev Prevents permissionless DoS - if VRF doesn't arrive, clear pendingEpoch
uint256 public constant EPOCH_VRF_TIMEOUT = 1 hours;

/// @notice Minimum interval between epoch starts (V3.3)
/// @dev Prevents epoch-spam DoS. Rate limits startNewEpoch() calls.
uint256 public constant EPOCH_MIN_INTERVAL = 4 hours;

/// @notice Timeout for finalization after VRF fulfillment (V3.3.4)
/// @dev If VRF arrived but nobody started finalization within this window,
///      allow cancel as escape hatch. Once rebuild starts, cancel is blocked forever.
uint256 public constant EPOCH_FINALIZE_TIMEOUT = 6 hours;

/// @notice Maximum τ value (at max retry round) - CORRECTED in V3.3.5
/// @dev τ_max = EXPECTED_COMMITTEE_SIZE + (MAX_ROUNDS - 1) * TAU_ROUND_INCREMENT
///      = 7 + (3-1) * 2 = 7 + 4 = 11 (NOT 13! Rounds are 0-indexed: 0,1,2)
uint256 public constant TAU_MAX = 11;

/// @notice Safety factor for bucket-aware concentration cap (V3.3.5)
/// @dev Ensures verifier has < 50% selection probability at any bucket tier
uint256 public constant CONCENTRATION_FACTOR = 2;

/// @notice Minimum verifier count before concentration cap is enforced (V3.3.4)
/// @dev During bootstrap with few verifiers, allow higher concentration
///      Once network has enough verifiers, enforce the cap
uint256 public constant CONCENTRATION_ENFORCEMENT_MIN = 10;

/// @notice Bond required to call startNewEpoch (V3.3.5)
/// @dev Prevents permissionless VRF subscription drain. Returned on finalization.
///      If epoch is cancelled, bond is slashed to treasury.
uint256 public constant EPOCH_STARTER_BOND = 10e6; // 10 USDC

/// @notice Reward per finalization chunk (in USDC, 6 decimals)
/// @dev Paid from slashing treasury to incentivize timely finalization
///      V3.3.4: Reward is now proportional to actual progress (see finalizeEpochChunk)
uint256 public constant FINALIZE_CHUNK_REWARD = 1e6; // 1 USDC per chunk (prorated)

/// @notice Slash percentage for commit-no-reveal (V3.2)
/// @dev 10% of stake slashed for committing but failing to reveal
uint256 public constant NO_REVEAL_SLASH_BPS = 1000; // 10%

/// @notice Maximum batch value to ensure minStake fits bucket model (V3.3.2)
/// @dev minStake = 0.3 * batchValue. For bucket 13 (last bucket) lower bound = 8.192M,
///      we want minStake <= ~8M to stay in reasonable bucket range.
///      MAX_BATCH_VALUE = 8M / 0.3 ≈ 26.67M, round down to 25M for safety.
///      Batches above this cap must be split into smaller batches.
uint256 public constant MAX_BATCH_VALUE = 25_000_000e6; // 25M USDC
```

**DELETE these constants** (no longer applicable):
- `OVER_SELECTION_BUFFER` - replaced by τ > QUORUM

---

## Part 2: Modified Verifier Struct (VerifierNetwork.sol)

Replace the Verifier struct (around line 102):

```solidity
/// @notice Verifier registration and state
struct Verifier {
    uint256 stakedAmount;       // USDC staked (live, includes unbonding until claimed)
    uint256 selectionStake;     // Epoch-locked stake for selection (snapshot)
    uint256 unbondingAmount;    // Amount marked for unbonding (still slashable!)
    uint256 pendingRewards;     // Accumulated rewards
    uint256 minorityVotes;      // Times voted with minority (per-asset)
    uint256 totalVotes;         // Total asset-votes cast
    uint256 assignedBatches;    // Total batches participated in
    uint40 registeredAt;        // Registration timestamp
    uint40 lastSlashTime;       // Last time slashed
    uint40 unbondingStart;      // When unbonding started
    uint8 minorityWarnings;     // Warning count for minority voting
    uint8 participationWarnings; // Warning count for low participation
    bool isActive;              // Currently active
    // NOTE: stakeBucket removed - computed on-demand from selectionStake
}
```

---

## Part 3: Modified Batch Struct (VerifierNetwork.sol)

Replace the Batch struct (around line 119):

```solidity
/// @notice Batch for commit-reveal voting (per-asset consensus)
struct Batch {
    // ─── Slot 0 (dynamic array pointer) ───
    uint64[] assetIds;          // Assets in this batch
    // ─── Slot 1 ─── (16+16 = 32 bytes, packed)
    uint128 totalValue;         // Sum of trade values (USDC)
    uint128 creatorDeposit;     // Deposit paid by creator
    // ─── Slot 2 ─── (packed: 5+5+5+5+1+2+1+1 = 25 bytes)
    uint40 commitDeadline;      // End of commit phase (current round)
    uint40 revealDeadline;      // End of reveal phase (current round)
    uint40 executedAt;          // When batch was executed
    uint40 createdAt;           // When batch was created
    BatchState state;           // Current state (1 byte)
    uint16 revealCount;         // Reveals in current round (uint16 prevents overflow)
    uint8 currentRound;         // Current retry round (0-indexed)
    bool isAuditBatch;          // True if audit re-vote batch
    // ─── Slot 3 ───
    address creator;            // Who created the batch
    uint64 arweaveBlock;        // Arweave block height
    // ─── Slot 4 ───
    address executor;           // Who triggered execution
    // ─── Slot 5 ───
    uint256 batchEpoch;         // Epoch when batch was created (for seed)
    // ─── Slot 6 ─── (V3.3: stored entropy for anti-grinding)
    bytes32 createdEntropy;     // block.prevrandao at creation (avoids 256-block staleness)
}
```

---

## Part 4: New Storage Variables (VerifierNetwork.sol)

Add after existing storage variables (around line 440):

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// SELECTION BUCKET SNAPSHOT (epoch-locked, prevents grinding)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Total selection stake in each bucket (SNAPSHOT)
/// @dev bucketStakeSumSel[i] = sum of selectionStakes where BUCKET_BASE × 2^i <= stake < BUCKET_BASE × 2^(i+1)
/// @dev Updated by: epoch finalization, slash, suspend (forced changes)
uint256[14] public bucketStakeSumSel;

/// @notice Count of verifiers in each bucket (SNAPSHOT - for liveness checks)
/// @dev bucketCountSel[i] = number of verifiers with stake in bucket i
/// @dev Used to verify eligibleCount >= QUORUM before batch creation
uint256[14] public bucketCountSel;

/// @notice Total selection stake across all verifiers (SNAPSHOT)
/// @dev Used for batch cap calculation
uint256 public totalSelectionStake;

/// @notice Total count of verifiers with selection stake (SNAPSHOT)
/// @dev Used for liveness verification
uint256 public totalSelectionCount;

// ═══════════════════════════════════════════════════════════════════════════
// SUFFIX SUM CACHES (O(1) eligibility lookups instead of O(14))
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Suffix sum of selection stake from bucket i onwards
/// @dev eligibleStakeFromBucket[i] = Σ_{j>=i} bucketStakeSumSel[j]
/// @dev Computed at epoch swap, updated on forced changes
uint256[14] public eligibleStakeFromBucket;

/// @notice Suffix sum of verifier count from bucket i onwards
/// @dev eligibleCountFromBucket[i] = Σ_{j>=i} bucketCountSel[j]
uint256[14] public eligibleCountFromBucket;

// ═══════════════════════════════════════════════════════════════════════════
// EPOCH MANAGEMENT (single pending epoch + chunked finalization)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Active epoch with fulfilled + finalized VRF (used for batch selection)
uint256 public activeEpoch;

/// @notice Pending epoch awaiting VRF fulfillment (0 if none pending)
/// @dev Only one pending epoch allowed at a time
uint256 public pendingEpoch;

/// @notice Whether epoch finalization is complete
/// @dev epochId => finalized (VRF fulfilled AND all verifiers snapshotted)
mapping(uint256 => bool) public epochFinalized;

/// @notice Progress of chunked epoch finalization
/// @dev epochId => number of verifiers processed so far
mapping(uint256 => uint256) public epochFinalizedUpTo;

// ═══════════════════════════════════════════════════════════════════════════
// PER-BATCH PARTICIPATION TRACKING (one participation per batch)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Round when verifier committed (0 = never committed to this batch)
/// @dev batchId => verifier => round+1 (0 means no commit ever)
/// @dev IMPORTANT: Once committed to any round, cannot commit again for this batch
mapping(bytes32 => mapping(address => uint8)) public committedRoundPlus1;

/// @notice Round when verifier revealed (0 = never revealed for this batch)
/// @dev batchId => verifier => round+1 (0 means no reveal ever)
mapping(bytes32 => mapping(address => uint8)) public revealedRoundPlus1;

/// @notice Committers per round (for metrics/iteration)
/// @dev batchId => round => committer addresses
mapping(bytes32 => mapping(uint8 => address[])) public roundCommitters;

/// @notice Vote counts per round (for per-round consensus check)
/// @dev batchId => round => assetId => Decision => count
/// @dev IMPORTANT: Use uint16 to prevent overflow on tail cases (τ can exceed 255 with retries)
mapping(bytes32 => mapping(uint8 => mapping(uint64 => mapping(Decision => uint16)))) public assetVoteCountsR;

/// @notice Refund reason counts per round
/// @dev batchId => round => assetId => RefundReason => count
/// @dev IMPORTANT: Use uint16 to prevent overflow
mapping(bytes32 => mapping(uint8 => mapping(uint64 => mapping(RefundReason => uint16)))) public assetRefundReasonCountsR;

// ═══════════════════════════════════════════════════════════════════════════
// BATCH COLLISION PREVENTION (V3.2)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Monotonic nonce for unique batchId generation
/// @dev Prevents batchId collision when same params in same block
uint256 public batchNonce;

// ═══════════════════════════════════════════════════════════════════════════
// FINALIZER REWARDS (V3.3: pull pattern for reentrancy safety)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Accumulated finalization rewards (pull pattern)
/// @dev Rewards accumulated here, withdrawn via claimFinalizerRewards()
mapping(address => uint256) public finalizerRewards;

/// @notice Timestamp of last epoch start (for rate limiting)
/// @dev V3.3: Used to enforce EPOCH_MIN_INTERVAL
uint256 public lastEpochStartTime;

// ═══════════════════════════════════════════════════════════════════════════
// V3.3.3: REBUILD-SAFE SLASHING SUPPORT
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Tracks which epoch a verifier's selectionStake was snapshotted for
/// @dev V3.3.3: When selectionEpochTag[v] == pendingEpoch, verifier was already
///      processed into Next arrays. Slashing must apply delta corrections to Next.
mapping(address => uint256) internal selectionEpochTag;

/// @notice Per-round reveal deadlines for accurate slashNoReveal enforcement
/// @dev V3.3.3: batch.revealDeadline changes on retry, so we need per-round tracking
///      batchId => round => revealDeadline (timestamp when round's reveal window ended)
mapping(bytes32 => mapping(uint8 => uint40)) public roundRevealDeadline;

// ═══════════════════════════════════════════════════════════════════════════
// V3.3.4: EPOCH ID REUSE PREVENTION + DEFERRED SUSPENSION
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Monotonic nonce for epoch ID generation (prevents epoch ID reuse after cancel)
/// @dev V3.3.4: Epoch ID = ++epochNonce. After cancel, old VRF request can't match new epoch.
uint256 public epochNonce;

/// @notice Tracks verifiers pending suspension (deferred during rebuild)
/// @dev V3.3.4: When suspension is blocked during rebuild, mark here for later processing
///      verifier => true if suspension is pending
mapping(address => bool) public needsSuspension;

/// @notice Timestamp when VRF was fulfilled (for EPOCH_FINALIZE_TIMEOUT)
/// @dev V3.3.4: Used to calculate timeout for fulfilled-but-no-progress escape hatch
mapping(uint256 => uint40) public epochFulfilledAt;

/// @notice Nonce for audit batch ID generation (prevents audit batchId collision)
/// @dev V3.3.4: Separate from batchNonce for clarity
uint256 public auditBatchNonce;

// ═══════════════════════════════════════════════════════════════════════════
// V3.3.5: EPOCH STARTER BOND + STALE EPOCH ERROR
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Who started the current pending epoch (receives bond back on finalization)
/// @dev V3.3.5: Prevents permissionless VRF subscription drain
address public epochStarter;

/// @notice Bond deposited by epoch starter (returned on finalization, slashed on cancel)
/// @dev V3.3.5: Stored per epoch to allow bond changes between epochs
mapping(uint256 => uint256) public epochStarterBonds;
```

---

## Part 5: Bucket and Selection Functions (VerifierNetwork.sol)

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// BUCKET MANAGEMENT (selection snapshot only)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @notice Calculate bucket index for a stake amount
 * @dev Uses log₂ scale from BUCKET_BASE: bucket[i] = stakes where BASE × 2^i <= stake < BASE × 2^(i+1)
 *      GAS OPTIMIZATION: Uses bit-scan (binary search for MSB) instead of while loop
 * @param stake The stake amount in USDC (6 decimals)
 * @return Bucket index (0 to MAX_BUCKETS-1)
 */
function _getBucket(uint256 stake) internal pure returns (uint8) {
    if (stake < BUCKET_BASE) return 0; // Below minimum, bucket 0

    uint256 normalized = stake / BUCKET_BASE;

    // GAS OPTIMIZATION: Binary search for most significant bit (log₂)
    // Much faster than while loop for large stakes
    uint8 bucket = 0;
    if (normalized >= 1 << 8) { normalized >>= 8; bucket += 8; }
    if (normalized >= 1 << 4) { normalized >>= 4; bucket += 4; }
    if (normalized >= 1 << 2) { normalized >>= 2; bucket += 2; }
    if (normalized >= 1 << 1) { bucket += 1; }

    // Clamp to MAX_BUCKETS - 1
    if (bucket >= MAX_BUCKETS) bucket = uint8(MAX_BUCKETS - 1);

    return bucket;
}

/**
 * @notice Get bucket lower bound (minimum stake for that bucket)
 * @param bucket The bucket index
 * @return Lower bound stake amount
 */
function _getBucketLowerBound(uint8 bucket) internal pure returns (uint256) {
    return BUCKET_BASE << bucket; // BUCKET_BASE × 2^bucket
}

/**
 * @notice Get total eligible selection stake for a minimum stake requirement
 * @dev O(1) using pre-computed suffix sum cache
 * @param minStake Minimum stake to be eligible
 * @return Total selection stake from verifiers meeting minimum
 */
function _getEligibleStake(uint256 minStake) internal view returns (uint256) {
    uint8 minBucket = _getMinBucket(minStake);
    if (minBucket >= MAX_BUCKETS) return 0;
    return eligibleStakeFromBucket[minBucket]; // O(1) lookup!
}

/**
 * @notice Get count of eligible verifiers for a minimum stake requirement
 * @dev O(1) using pre-computed suffix sum cache
 * @param minStake Minimum stake to be eligible
 * @return Number of verifiers meeting minimum stake requirement
 */
function _getEligibleCount(uint256 minStake) internal view returns (uint256) {
    uint8 minBucket = _getMinBucket(minStake);
    if (minBucket >= MAX_BUCKETS) return 0;
    return eligibleCountFromBucket[minBucket]; // O(1) lookup!
}

// V3.3.3: Explicit revert for minStake exceeding bucket model
error MinStakeOutOfRange(uint256 minStake, uint256 maxSupported);

/**
 * @notice Get minimum bucket index for a stake requirement
 * @dev Rounds UP to bucket boundary for conservative eligibility
 *
 *      V3.3.2 FIX: Last bucket is OPEN-ENDED [BASE*2^13, ∞)
 *      - _getBucket() clamps large stakes to bucket 13
 *      - Therefore bucket 13 contains ALL stakes >= 8.192M
 *      - We NEVER return MAX_BUCKETS (would cause array out-of-bounds)
 *      - Batch value cap (MAX_BATCH_VALUE) ensures minStake stays reasonable
 *
 *      V3.3.3 FIX: EXPLICIT REVERT instead of silent clamp
 *      - If minStake > bucket 13 lower bound, we REVERT
 *      - This catches bugs early if MAX_BATCH_VALUE is ever increased
 *      - Better to fail loudly than silently select wrong committee
 *
 *      Example: minStake = 20M (should not happen with MAX_BATCH_VALUE cap)
 *      - _getBucket(20M) returns 13 (clamped)
 *      - 20M > lowerBound(13) = 8.192M, would round up to 14
 *      - V3.3.2: Clamped to 13 silently (DANGEROUS)
 *      - V3.3.3: REVERT with MinStakeOutOfRange (SAFE)
 */
function _getMinBucket(uint256 minStake) internal pure returns (uint8) {
    uint8 bucket = _getBucket(minStake);

    // Round up if minStake exceeds bucket lower bound
    if (minStake > _getBucketLowerBound(bucket)) {
        // V3.3.3 FIX: If at last bucket and need to round up, REVERT
        // This should never happen if MAX_BATCH_VALUE is set correctly
        if (bucket >= MAX_BUCKETS - 1) {
            revert MinStakeOutOfRange(minStake, _getBucketLowerBound(uint8(MAX_BUCKETS - 1)));
        }
        bucket++;
    }
    return bucket;
}

/**
 * @notice Add a verifier to selection snapshot
 * @dev Called during epoch finalization chunk processing
 */
function _addToSelectionSnapshot(address verifierAddr, uint256 stake) internal {
    Verifier storage v = verifiers[verifierAddr];
    v.selectionStake = stake;

    if (stake >= BUCKET_BASE) {
        uint8 bucket = _getBucket(stake);
        bucketStakeSumSel[bucket] += stake;
        bucketCountSel[bucket]++;
    }

    totalSelectionStake += stake;
    totalSelectionCount++;
}

/**
 * @notice Remove a verifier from selection snapshot
 * @dev Called on forced changes (slash, suspend, deactivation)
 *      Recomputes suffix caches after removal
 */
function _removeFromSelectionSnapshot(address verifierAddr) internal {
    Verifier storage v = verifiers[verifierAddr];
    uint256 stake = v.selectionStake;

    if (stake == 0) return; // Not in snapshot

    if (stake >= BUCKET_BASE) {
        uint8 bucket = _getBucket(stake);
        bucketStakeSumSel[bucket] -= stake;
        bucketCountSel[bucket]--;
    }

    totalSelectionStake -= stake;
    totalSelectionCount--;
    v.selectionStake = 0;

    // Recompute suffix caches after bucket change (O(14) - forced changes are rare)
    _recomputeSuffixCaches();
}

/**
 * @notice Update a verifier's selection stake (for slash)
 * @dev Removes from old bucket, adds to new bucket, recomputes suffix caches
 */
function _updateSelectionStake(address verifierAddr, uint256 newStake) internal {
    Verifier storage v = verifiers[verifierAddr];
    uint256 oldStake = v.selectionStake;

    if (oldStake == newStake) return;

    // Remove from old bucket
    if (oldStake > 0) {
        if (oldStake >= BUCKET_BASE) {
            uint8 oldBucket = _getBucket(oldStake);
            bucketStakeSumSel[oldBucket] -= oldStake;
            bucketCountSel[oldBucket]--;
        }
        totalSelectionStake -= oldStake;
        totalSelectionCount--;
    }

    // Add to new bucket
    v.selectionStake = newStake;
    if (newStake > 0) {
        if (newStake >= BUCKET_BASE) {
            uint8 newBucket = _getBucket(newStake);
            bucketStakeSumSel[newBucket] += newStake;
            bucketCountSel[newBucket]++;
        }
        totalSelectionStake += newStake;
        totalSelectionCount++;
    }

    // Recompute suffix caches after bucket change (O(14) - forced changes are rare)
    _recomputeSuffixCaches();
}

// ═══════════════════════════════════════════════════════════════════════════
// SELF-SELECTION (stake-weighted public lottery)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @notice Get expected committee size for a round
 * @dev τ_round = τ + round * 2 (compensates for excluded prior participants)
 */
function _getExpectedCommitteeSize(uint8 round) internal pure returns (uint256) {
    return EXPECTED_COMMITTEE_SIZE + (uint256(round) * TAU_ROUND_INCREMENT);
}

/**
 * @notice Check if a verifier is selected for a batch/round
 * @dev Implements stake-weighted sortition using SELECTION SNAPSHOT:
 *      1. Calculate per-round seed: H(epochSeed, batchId, round, blockhash)
 *      2. Calculate verifier's roll: H(roundSeed, verifier) - FULL 256-bit
 *      3. Calculate threshold: (selectionStake × τ_round × 2^256) / eligibleSelectionStake
 *      4. Selected if roll < threshold
 *
 * CRITICAL: Uses selectionStake and bucketStakeSumSel (epoch-locked snapshots)
 *           NOT stakedAmount or live buckets (prevents grinding)
 *
 * V3.2/V3.3 FIXES:
 * - Uses stored createdEntropy (V3.3: avoids 256-block blockhash staleness)
 * - Uses effective minStake snapped to bucket boundary (V3.2: consistency)
 * - Uses Math.mulDiv for 256-bit precision (V3.3: prevents overflow)
 *
 * @param batchId The batch to check selection for
 * @param round The retry round (0-indexed)
 * @param verifier The verifier to check
 * @return True if verifier is selected for this batch/round
 */
function _isSelected(
    bytes32 batchId,
    uint8 round,
    address verifier
) internal view returns (bool) {
    Verifier storage v = verifiers[verifier];
    if (!v.isActive) return false;

    Batch storage batch = batches[batchId];
    Epoch storage epoch = epochs[batch.batchEpoch];

    // V3.3.4 FIX: Removed `randomSeed == 0` check - seed 0 is valid!
    // The fulfilled flag is the authoritative indicator of VRF completion
    // Old: if (!epoch.fulfilled || epoch.randomSeed == 0) return false;
    if (!epoch.fulfilled) return false;
    if (!epochFinalized[batch.batchEpoch]) return false; // Must be finalized

    // Use SELECTION stake (epoch-locked snapshot)
    uint256 stake = v.selectionStake;

    // V3.2 FIX: Use EFFECTIVE min stake snapped to bucket boundary
    // This ensures consistency between eligibility check and denominator
    uint256 minStakeRaw = _getMinStake(batch.totalValue);
    uint8 minBucket = _getMinBucket(minStakeRaw);
    uint256 minStakeEff = _getBucketLowerBound(minBucket);

    if (stake < minStakeEff) return false;

    // Get eligible stake from SELECTION buckets (snapshot)
    uint256 eligibleStake = eligibleStakeFromBucket[minBucket];
    if (eligibleStake == 0) return false;

    // V3.3 FIX: Use stored entropy (avoids 256-block staleness of blockhash)
    // createdEntropy was set to block.prevrandao at batch creation time
    bytes32 roundSeed = keccak256(abi.encode(epoch.randomSeed, batchId, round, batch.createdEntropy));

    // V3.2/V3.3 FIX: 256-bit roll precision with mulDiv (prevents quantization + overflow)
    uint256 roll = uint256(keccak256(abi.encode(roundSeed, verifier)));

    // Dynamic τ for this round
    uint256 tau = _getExpectedCommitteeSize(round);

    // V3.3.3 FIX: Overflow-safe stake*tau multiplication
    // With MAX_BUCKETS=14 and BUCKET_BASE=1000e6, max stake in model is ~16M USDC
    // V3.3.5 CORRECTION: τ_max = 7 + (MAX_ROUNDS-1) * 2 = 7 + 2*2 = 11 (rounds are 0-indexed: 0,1,2)
    // 16M * 11 = 176M << 2^128, so this should never overflow in practice
    // But defense-in-depth: check and handle gracefully
    uint256 numerator;
    unchecked {
        numerator = stake * tau;
        // V3.3.3: If overflow occurred (numerator wrapped), treat as 100% selection
        // This is safe: worst case is extra verifiers get selected
        if (numerator / tau != stake) {
            return true; // Overflow → always selected (safe failure mode)
        }
    }

    if (numerator >= eligibleStake) {
        // Would exceed 100% - always selected
        return true;
    }

    // V3.3: Math.mulDiv(a, b, c) computes (a * b) / c with 512-bit intermediate
    uint256 threshold = Math.mulDiv(numerator, type(uint256).max, eligibleStake);

    return roll < threshold;
}

/**
 * @notice Calculate minimum stake required for batch eligibility
 * @dev Based on cryptoeconomic security: min_stake = α × V / (QUORUM × slash_rate)
 *      With α = 1.5, QUORUM = 5, slash_rate = 100%:
 *      min_stake = 1.5 × V / 5 = 0.3 × V
 * @param batchValue Total value of the batch
 * @return Minimum stake in USDC (6 decimals)
 */
function _getMinStake(uint256 batchValue) internal pure returns (uint256) {
    // min_stake = α × V / (QUORUM × slash_rate)
    // = 15000/10000 × V / (5 × 1.0) = 0.3 × V
    return (batchValue * 3000) / BPS;
}
```

---

## Part 5.5: Epoch Transition Helpers (VerifierNetwork.sol)

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// EPOCH TRANSITION STATE HELPERS
// ═══════════════════════════════════════════════════════════════════════════

// New errors
error EpochTransitioning();
error StakeFrozen();
error EpochNotStale();

// V3.3.4: Concentration cap error
error StakeExceedsMax(uint256 requested, uint256 maxAllowed);

// V3.3.6: Rebuild-start griefing protection error
error OnlyEpochStarterCanBegin();

/**
 * @notice Check if epoch is transitioning (blocks batch creation and commits)
 * @dev V3.3.4 FIX: Narrowed from "pendingEpoch != 0" to "rebuild in progress"
 *      Old behavior blocked operations even before VRF arrived
 *      New behavior only blocks during actual snapshot overwrite
 *
 *      True when pendingEpoch != 0 AND rebuild has started (epochFinalizedUpTo > 0)
 */
function _isEpochTransitioning() internal view returns (bool) {
    // V3.3.4: Only block during actual rebuild, not just when epoch is pending
    // This narrows the pause window from potentially hours (VRF latency) to seconds
    return _isSnapshotRebuilding(); // pendingEpoch != 0 && epochFinalizedUpTo[pendingEpoch] > 0
}

/**
 * @notice Check if stake mutations are frozen (blocks stake changes)
 * @dev True when pending epoch has VRF fulfilled but not yet finalized
 *      This prevents grinding: verifiers can't change stake after seeing seed
 */
function _isStakeFrozen() internal view returns (bool) {
    if (pendingEpoch == 0) return false;
    return epochs[pendingEpoch].fulfilled;
}

/**
 * @notice Check if snapshot is being rebuilt (blocks forced snapshot mutations)
 * @dev True when finalization has started (first chunk processed)
 *      During this window, forced changes must not touch snapshot arrays
 */
function _isSnapshotRebuilding() internal view returns (bool) {
    if (pendingEpoch == 0) return false;
    return epochFinalizedUpTo[pendingEpoch] > 0;
}

/**
 * @notice Cancel a stale pending epoch (escape hatch for DoS prevention)
 * @dev Permissionless - anyone can call if timeout exceeded
 *      CRITICAL: Can only cancel BEFORE finalization chunks start!
 *      Once rebuild starts (epochFinalizedUpTo > 0), verifier.selectionStake
 *      is being overwritten - canceling would corrupt active epoch selection.
 *
 *      V3.3.4 FIX: Two cancel paths now supported:
 *      1. VRF not fulfilled within EPOCH_VRF_TIMEOUT (original path)
 *      2. VRF fulfilled but no one started finalization within EPOCH_FINALIZE_TIMEOUT (new)
 */
function cancelStaleEpoch() external {
    if (pendingEpoch == 0) revert EpochNotStale();

    // CRITICAL: Cannot cancel after rebuild has started!
    // verifier.selectionStake is being overwritten - would corrupt active epoch
    if (epochFinalizedUpTo[pendingEpoch] > 0) revert EpochNotStale();

    Epoch storage epoch = epochs[pendingEpoch];

    // V3.3.4: Two cancel paths
    bool canCancel = false;

    if (!epoch.fulfilled) {
        // Path 1: VRF never arrived - cancel after EPOCH_VRF_TIMEOUT
        uint256 elapsed = block.timestamp - epoch.startTime;
        if (elapsed > EPOCH_VRF_TIMEOUT) {
            canCancel = true;
        }
    } else {
        // Path 2 (V3.3.4): VRF arrived but nobody started finalization
        // Cancel after EPOCH_FINALIZE_TIMEOUT from fulfillment time
        uint256 elapsedSinceFulfill = block.timestamp - epochFulfilledAt[pendingEpoch];
        if (elapsedSinceFulfill > EPOCH_FINALIZE_TIMEOUT) {
            canCancel = true;
        }
    }

    if (!canCancel) revert EpochNotStale();

    // Reset epoch state
    uint256 staleEpoch = pendingEpoch;
    uint256 staleRequestId = epoch.vrfRequestId;
    pendingEpoch = 0;

    // V3.3.5 FIX: Slash epoch-starter bond to treasury
    // This disincentivizes starting epochs without intending to finalize them
    uint256 bond = epochStarterBonds[staleEpoch];
    if (bond > 0) {
        epochStarterBonds[staleEpoch] = 0;
        slashingTreasury += bond;
        emit EpochStarterBondSlashed(epochStarter, staleEpoch, bond);
    }
    epochStarter = address(0);

    // V3.3.4 FIX: Clean up vrfRequestToEpoch mapping to prevent late fulfillment issues
    // (Though with the vrfRequestId check in fulfillRandomWords, this is belt-and-suspenders)
    delete vrfRequestToEpoch[staleRequestId];

    // SAFETY: Finalization never started (epochFinalizedUpTo[pendingEpoch] == 0)
    // - Active buckets (bucketStakeSumSel) unchanged
    // - verifier.selectionStake unchanged (chunks never ran)
    // - suffix caches unchanged
    // System returns to using activeEpoch's snapshot (fully intact)

    emit EpochCancelled(staleEpoch);
}

// V3.3.5: Event for bond slashing
event EpochStarterBondSlashed(address indexed starter, uint256 indexed epochId, uint256 amount);

// New event
event EpochCancelled(uint256 indexed epochId);
```

---

## Part 6: Chunked Epoch Finalization (VerifierNetwork.sol)

Add new storage for building next snapshot (separate from active):

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// NEXT EPOCH SNAPSHOT (built during finalization, swapped on completion)
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Next epoch bucket sums (built during finalization)
uint256[14] internal bucketStakeSumNext;

/// @notice Next epoch bucket counts (built during finalization)
uint256[14] internal bucketCountNext;

/// @notice Next epoch total stake (built during finalization)
uint256 internal totalSelectionStakeNext;

/// @notice Next epoch total count (built during finalization)
uint256 internal totalSelectionCountNext;
```

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// EPOCH FINALIZATION (chunked for gas safety)
// ═══════════════════════════════════════════════════════════════════════════

// V3.3 error
error NoRewardsToClaim();

/**
 * @notice Process a chunk of verifiers for epoch finalization
 * @dev Permissionless - anyone can call to help finalize
 *      MUST be called after VRF fulfillment, before epoch becomes active
 *      CRITICAL: Builds into "Next" arrays, only swaps on completion
 *      This makes cancellation safe (old snapshot remains valid)
 *
 *      GAS OPTIMIZATION: Uses memory accumulators instead of per-verifier SSTORE.
 *      Reduces ~200 SSTORE per chunk to ~30 SSTORE (14+14+2 at end).
 *
 *      V3.2 INCENTIVE: Pays FINALIZE_CHUNK_REWARD from slashing treasury.
 *      V3.3 FIX: count guard + progress check + pull pattern + nonReentrant
 *
 * @param epochId The epoch to finalize (MUST equal pendingEpoch)
 * @param count Number of verifiers to process in this chunk (MUST be > 0)
 */
function finalizeEpochChunk(uint256 epochId, uint256 count) external nonReentrant {
    // V3.3 FIX: Prevent count=0 reward drain
    if (count == 0) revert InvalidInput();

    // CRITICAL: Must finalize the pending epoch only
    if (epochId != pendingEpoch) revert InvalidInput(); // "Must finalize pendingEpoch"

    Epoch storage epoch = epochs[epochId];

    // Must be fulfilled but not yet finalized
    if (!epoch.fulfilled) revert VRFNotReady();
    if (epochFinalized[epochId]) revert InvalidInput(); // Already finalized

    // For first chunk, clear NEXT arrays (not active ones!)
    uint256 start = epochFinalizedUpTo[epochId];
    if (start == 0) {
        // V3.3.6 FIX: Only epochStarter can initiate first chunk
        // Prevents griefing where attacker calls finalizeEpochChunk(epochId, 1) to start
        // rebuild, blocking cancel forever while making minimal progress
        if (msg.sender != epochStarter) revert OnlyEpochStarterCanBegin();
        for (uint8 i = 0; i < MAX_BUCKETS; i++) {
            bucketStakeSumNext[i] = 0;
            bucketCountNext[i] = 0;
        }
        totalSelectionStakeNext = 0;
        totalSelectionCountNext = 0;
    }

    // Process chunk into NEXT arrays
    uint256 end = start + count;
    if (end > activeVerifierList.length) {
        end = activeVerifierList.length;
    }

    // ═══════════════════════════════════════════════════════════════════════
    // GAS OPTIMIZATION: Memory accumulators instead of per-verifier SSTORE
    // ═══════════════════════════════════════════════════════════════════════
    uint256[14] memory localBucketSum;
    uint256[14] memory localBucketCount;
    uint256 localTotalStake = 0;
    uint256 localTotalCount = 0;

    for (uint256 i = start; i < end; ) {
        address v = activeVerifierList[i];
        Verifier storage verifier = verifiers[v];

        // Snapshot: selection stake = current staked amount (includes unbonding)
        uint256 stake = verifier.stakedAmount;

        // Store in verifier (this is OK, will be overwritten on cancel anyway)
        verifier.selectionStake = stake;

        // V3.3.3 FIX: Track which epoch this verifier was snapshotted for
        // This enables delta corrections if slashing occurs during rebuild
        selectionEpochTag[v] = epochId;

        // Accumulate in MEMORY (not storage!)
        if (stake >= BUCKET_BASE) {
            uint8 bucket = _getBucket(stake);
            localBucketSum[bucket] += stake;
            localBucketCount[bucket]++;
        }
        localTotalStake += stake;
        localTotalCount++;

        unchecked { ++i; }
    }

    // Single batch write to storage (14+14+2 = 30 SSTORE instead of 200+)
    for (uint8 b = 0; b < MAX_BUCKETS; ) {
        if (localBucketSum[b] > 0) {
            bucketStakeSumNext[b] += localBucketSum[b];
            bucketCountNext[b] += localBucketCount[b];
        }
        unchecked { ++b; }
    }
    totalSelectionStakeNext += localTotalStake;
    totalSelectionCountNext += localTotalCount;

    epochFinalizedUpTo[epochId] = end;

    // Check if complete
    if (end >= activeVerifierList.length) {
        _completeEpochFinalization(epochId);
    }

    // V3.3 FIX: Only pay reward if actual progress was made (end > start)
    // V3.3 FIX: Use pull pattern (accumulate, don't transfer) for reentrancy safety
    // V3.3.4 FIX: Proportional reward prevents "mining" with count=1
    // Old: if (end > start && ...) { reward = FINALIZE_CHUNK_REWARD }
    // New: reward = FINALIZE_CHUNK_REWARD * processed / EPOCH_FINALIZE_CHUNK_SIZE
    uint256 processed = end - start;
    if (processed > 0) {
        uint256 proratedReward = (FINALIZE_CHUNK_REWARD * processed) / EPOCH_FINALIZE_CHUNK_SIZE;
        if (proratedReward > 0 && slashingTreasury >= proratedReward) {
            slashingTreasury -= proratedReward;
            finalizerRewards[msg.sender] += proratedReward;  // Pull pattern
            emit FinalizationRewardPaid(msg.sender, proratedReward);
        }
    }

    emit EpochFinalizationProgress(epochId, end, activeVerifierList.length);
}

// V3.2 event
event FinalizationRewardPaid(address indexed finalizer, uint256 amount);

/**
 * @notice Claim accumulated finalization rewards (V3.3)
 * @dev Pull pattern: rewards accumulated in finalizerRewards[], withdrawn here
 */
function claimFinalizerRewards() external nonReentrant {
    uint256 amount = finalizerRewards[msg.sender];
    if (amount == 0) revert NoRewardsToClaim();
    finalizerRewards[msg.sender] = 0;
    usdc.safeTransfer(msg.sender, amount);
    emit FinalizerRewardsClaimed(msg.sender, amount);
}

// V3.3 event
event FinalizerRewardsClaimed(address indexed finalizer, uint256 amount);

/**
 * @notice Complete epoch finalization and make it active
 * @dev Called automatically when last chunk is processed
 *      CRITICAL: Swaps Next → Active arrays (atomic transition)
 *      Then recomputes suffix sum caches for O(1) eligibility lookups
 *      V3.3.5: Returns epoch-starter bond on successful completion
 */
function _completeEpochFinalization(uint256 epochId) internal {
    // SWAP: Next → Active (O(MAX_BUCKETS) = O(14))
    for (uint8 i = 0; i < MAX_BUCKETS; ) {
        bucketStakeSumSel[i] = bucketStakeSumNext[i];
        bucketCountSel[i] = bucketCountNext[i];
        unchecked { ++i; }
    }
    totalSelectionStake = totalSelectionStakeNext;
    totalSelectionCount = totalSelectionCountNext;

    // Recompute suffix sum caches (O(14) - done once per epoch)
    _recomputeSuffixCaches();

    // V3.3.6 FIX: Continuous concentration enforcement
    // After the snapshot swap, check if any verifier now exceeds concentration cap.
    // This catches the case where other verifiers withdrew, making remaining ones "whales".
    // We don't revert finalization (critical path), but mark over-concentrated verifiers.
    _checkContinuousConcentration();

    epochFinalized[epochId] = true;
    activeEpoch = epochId;
    pendingEpoch = 0; // Allow new epoch requests

    // V3.3.5 FIX: Return epoch-starter bond on successful finalization
    // This completes the incentive loop: starter pays bond, sees epoch through, gets bond back
    uint256 bond = epochStarterBonds[epochId];
    address starter = epochStarter;
    if (bond > 0 && starter != address(0)) {
        epochStarterBonds[epochId] = 0;
        epochStarter = address(0);
        usdc.safeTransfer(starter, bond);
        emit EpochStarterBondReturned(starter, epochId, bond);
    }

    // V3.3.5: REMOVED retrospective audit internal call
    // The V3.3.4 pattern of calling address(this).call was risky:
    // - Silent failure mode (success ignored)
    // - Reentrancy concerns
    // - Gas estimation challenges
    // Retrospective audits should be triggered externally by callers who want them.
    // Alternative: emit an event that off-chain keepers can monitor.

    emit EpochCompleted(epochId);
}

// V3.3.5: Event for bond return
event EpochStarterBondReturned(address indexed starter, uint256 indexed epochId, uint256 amount);

/**
 * @notice Check concentration cap for all verifiers after epoch finalization (V3.3.6)
 * @dev Called at the end of _completeEpochFinalization to catch "passive whales" -
 *      verifiers who exceeded the concentration cap because others withdrew.
 *
 *      Design decisions:
 *      - Does NOT revert finalization (critical path, must complete)
 *      - Does NOT immediately suspend (would need swap-pop, just finished rebuild)
 *      - Instead: marks over-concentrated verifiers for "soft suspension" via capped selection
 *
 *      Over-concentrated verifiers:
 *      - Their selectionStake is capped to maxAllowed for selection probability
 *      - They can still reveal/commit for existing batches
 *      - They must reduce stake or wait for more verifiers before full eligibility returns
 *
 *      This is a soft enforcement: the verifier isn't kicked out, but their influence
 *      is capped until the concentration issue is resolved naturally.
 */
function _checkContinuousConcentration() internal {
    // Skip during bootstrap phase
    if (activeVerifierCount < CONCENTRATION_ENFORCEMENT_MIN) return;

    // Iterate through all active verifiers and check concentration
    // This is O(n) but runs only once per epoch (acceptable)
    for (uint256 i = 0; i < activeVerifierList.length; ) {
        address v = activeVerifierList[i];
        uint256 stake = verifiers[v].selectionStake;

        if (stake > 0) {
            uint8 k = _getBucket(stake);
            uint256 eligible = eligibleStakeFromBucket[k];

            if (eligible > 0) {
                uint256 maxAllowed = eligible / (TAU_MAX * CONCENTRATION_FACTOR);

                if (stake > maxAllowed) {
                    // Cap selectionStake for this epoch (soft enforcement)
                    verifiers[v].selectionStake = maxAllowed;
                    emit ConcentrationCapApplied(v, stake, maxAllowed);
                }
            }
        }

        unchecked { ++i; }
    }
}

// V3.3.6: Event for concentration cap enforcement
event ConcentrationCapApplied(address indexed verifier, uint256 originalStake, uint256 cappedStake);

/**
 * @notice Recompute suffix sum caches from bucket arrays
 * @dev O(14) - called once per epoch finalization and after forced changes
 */
function _recomputeSuffixCaches() internal {
    uint256 runningStake = 0;
    uint256 runningCount = 0;

    // Build suffix sums from right to left
    for (uint8 i = MAX_BUCKETS; i > 0; ) {
        unchecked { --i; }
        runningStake += bucketStakeSumSel[i];
        runningCount += bucketCountSel[i];
        eligibleStakeFromBucket[i] = runningStake;
        eligibleCountFromBucket[i] = runningCount;
    }
}

// New events
event EpochFinalizationProgress(uint256 indexed epochId, uint256 processed, uint256 total);
event EpochCompleted(uint256 indexed epochId);
```

---

## Part 7: Phase Machine Functions (VerifierNetwork.sol)

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// PHASE MACHINE
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @notice Transition batch state based on time and participation
 * @dev Called at start of commit/reveal to ensure correct state
 *      Key optimization: Early READY transition when no commits (skip reveal window)
 * @param batchId The batch to poke
 * @return Current state after transition
 */
function _poke(bytes32 batchId) internal returns (BatchState) {
    Batch storage batch = batches[batchId];

    if (batch.state == BatchState.COMMIT_PHASE) {
        if (block.timestamp > batch.commitDeadline) {
            uint8 round = batch.currentRound;
            uint256 commitCount = roundCommitters[batchId][round].length;

            if (commitCount == 0) {
                // No commits - skip reveal window, go directly to READY for retry
                batch.state = BatchState.READY;
            } else {
                // Some commits - give them a chance to reveal
                batch.state = BatchState.REVEAL_PHASE;
            }
        }
    }

    if (batch.state == BatchState.REVEAL_PHASE) {
        if (block.timestamp > batch.revealDeadline) {
            // Try to reach consensus with current votes
            _tryAutoExecuteRound(batchId, batch.currentRound);

            // If still not executed, move to READY for retry
            if (batch.state != BatchState.EXECUTED) {
                batch.state = BatchState.READY;
            }
        }
    }

    return batch.state;
}

// V3.3.6 FIX: Removed duplicate error declaration - StaleEpochBatch is defined in submitCommit section
// error StaleEpochBatch(bytes32 batchId, uint256 batchEpoch, uint256 currentEpoch);

/**
 * @notice Open next retry round or fail the batch
 * @dev Called from retryBatchSelection (in extension)
 *      CRITICAL: Fails batches from old epochs (single snapshot constraint)
 * @param batchId The batch to retry
 */
function _openNextRoundOrFail(bytes32 batchId) internal {
    Batch storage batch = batches[batchId];

    // EPOCH-BOUND CHECK: Cannot retry batches from old epochs
    // Single snapshot was overwritten - selection would be inconsistent
    if (batch.batchEpoch != activeEpoch) {
        _handleBatchFailure(batchId);
        emit StaleEpochBatchFailed(batchId, batch.batchEpoch, activeEpoch);
        return;
    }

    if (batch.currentRound >= MAX_ROUNDS - 1) {
        // Max rounds exceeded - fail batch
        _handleBatchFailure(batchId);
        return;
    }

    // Open new round
    batch.currentRound++;
    batch.revealCount = 0;
    batch.commitDeadline = uint40(block.timestamp + COMMIT_WINDOW);
    batch.revealDeadline = uint40(block.timestamp + COMMIT_WINDOW + REVEAL_WINDOW);
    batch.state = BatchState.COMMIT_PHASE;

    // Note: No verifier re-selection - self-selection uses new per-round seed
    // Note: τ increases with round to compensate for excluded prior participants
    emit BatchRetried(batchId, batch.currentRound, new address[](0));
}

// New event
event StaleEpochBatchFailed(bytes32 indexed batchId, uint256 batchEpoch, uint256 activeEpoch);

/**
 * @notice Try to execute round if quorum reached for all assets
 * @dev Checks per-round vote counts and updates assetConsensus
 * @param batchId The batch to check
 * @param round The round to check
 */
function _tryAutoExecuteRound(bytes32 batchId, uint8 round) internal {
    Batch storage batch = batches[batchId];
    if (batch.state == BatchState.EXECUTED) return;

    uint256 n = batch.assetIds.length;
    uint256 decided = 0;

    for (uint256 i = 0; i < n; i++) {
        uint64 assetId = batch.assetIds[i];

        // Skip if already has consensus from previous round
        if (assetConsensus[batchId][assetId].hasConsensus) {
            decided++;
            continue;
        }

        // Get per-round vote counts (uint16 to prevent overflow)
        uint16 claimC = assetVoteCountsR[batchId][round][assetId][Decision.CLAIM];
        uint16 refundC = assetVoteCountsR[batchId][round][assetId][Decision.REFUND];
        uint16 invalidC = assetVoteCountsR[batchId][round][assetId][Decision.INVALID];

        // Find max and detect ties
        Decision bestD = Decision.CLAIM;
        uint16 bestC = claimC;
        bool tie = false;

        if (refundC > bestC) {
            bestC = refundC;
            bestD = Decision.REFUND;
            tie = false;
        } else if (refundC == bestC && refundC != 0) {
            tie = true;
        }

        if (invalidC > bestC) {
            bestC = invalidC;
            bestD = Decision.INVALID;
            tie = false;
        } else if (invalidC == bestC && invalidC != 0) {
            tie = true;
        }

        // Need QUORUM with no tie
        if (bestC < QUORUM || tie) continue;

        // Get refund reason if needed
        RefundReason reason = RefundReason.None;
        if (bestD == Decision.REFUND) {
            reason = _pickRefundReasonR(batchId, round, assetId);
        }

        // Record consensus
        assetConsensus[batchId][assetId] = AssetConsensus({
            decision: bestD,
            refundReason: reason,
            votesFor: uint8(bestC > 255 ? 255 : bestC),  // Cap for storage (consensus already reached)
            hasConsensus: true
        });

        emit AssetConsensusReached(batchId, assetId, bestD, reason);
        decided++;
    }

    // All assets decided - execute!
    if (decided == n) {
        _executeBatchInternal(batchId);
        // Note: _executeBatchInternal sets state to EXECUTED
    }
}

/**
 * @notice Get majority refund reason for round
 */
function _pickRefundReasonR(
    bytes32 batchId,
    uint8 round,
    uint64 assetId
) internal view returns (RefundReason) {
    uint16 maxVotes = 0;
    RefundReason majorityReason = RefundReason.None;

    uint16 v1 = assetRefundReasonCountsR[batchId][round][assetId][RefundReason.FailedDelivery];
    if (v1 > maxVotes) { maxVotes = v1; majorityReason = RefundReason.FailedDelivery; }

    uint16 v2 = assetRefundReasonCountsR[batchId][round][assetId][RefundReason.TradeReversed];
    if (v2 > maxVotes) { maxVotes = v2; majorityReason = RefundReason.TradeReversed; }

    uint16 v3 = assetRefundReasonCountsR[batchId][round][assetId][RefundReason.TradeDeclined];
    if (v3 > maxVotes) { maxVotes = v3; majorityReason = RefundReason.TradeDeclined; }

    uint16 v4 = assetRefundReasonCountsR[batchId][round][assetId][RefundReason.Expired];
    if (v4 > maxVotes) { majorityReason = RefundReason.Expired; }

    return majorityReason;
}

/**
 * @notice Handle batch failure (refund all assets)
 * @dev Called when max rounds exceeded or timeout
 */
function _handleBatchFailure(bytes32 batchId) internal {
    Batch storage batch = batches[batchId];
    batch.state = BatchState.EXECUTED;
    batch.executedAt = uint40(block.timestamp);

    uint64[] memory assetIds = batch.assetIds;
    uint64[] memory refundAssets = new uint64[](assetIds.length);
    IJJSKIN.RefundReason[] memory refundReasons = new IJJSKIN.RefundReason[](assetIds.length);

    for (uint256 i = 0; i < assetIds.length; i++) {
        refundAssets[i] = assetIds[i];
        refundReasons[i] = IJJSKIN.RefundReason.Expired;
        settledAssets[assetIds[i]] = true;
        pendingAssets[assetIds[i]] = bytes32(0);
    }

    IJJSKIN(jjskin).batchExecuteDecisions(new uint64[](0), refundAssets, refundReasons);

    emit BatchSettled(batchId, Decision.REFUND, assetIds);
    emit BatchFailed(batchId, "Max rounds exceeded or timeout");
}
```

---

## Part 8: Modified createBatchFromArweave (VerifierNetwork.sol)

Replace the function (around line 907):

```solidity
// New errors
error InsufficientEligibleVerifiers(uint256 eligible, uint256 required);
error BatchIdCollision();  // V3.2
error BatchValueTooHigh(uint256 value, uint256 max);  // V3.3.2

/**
 * @notice Create a batch from Arweave-stored proofs (permissionless)
 * @dev V2: No verifier assignment - self-selection at commit time
 *      Records batch epoch for deterministic seed
 *      Checks liveness: eligibleCount >= QUORUM + 1
 *      BLOCKED when VRF fulfilled but not finalized (prevents grinding)
 *
 * V3.2/V3.3/V3.3.5 FIXES:
 * - Uses effective minStake (bucket-snapped) for liveness check (V3.2)
 * - Stores createdEntropy at creation (V3.3: avoids 256-block staleness)
 * - Uses batchNonce for collision prevention (V3.2)
 * - V3.3.5: Blocks when stake frozen (VRF fulfilled), not just during rebuild
 * - V3.3.5: Removed randomSeed==0 check (seed 0 is valid)
 */
function createBatchFromArweave(
    uint64[] calldata assetIds,
    uint64 arweaveBlock
) external returns (bytes32 batchId) {
    // V3.3.5 FIX: Block batch creation when VRF is fulfilled but not finalized
    // This prevents grinding: once seed is public, batch creator could influence batchId
    // to prefer a colluding committee. Use _isStakeFrozen() instead of _isEpochTransitioning().
    if (_isStakeFrozen()) revert StakeFrozen();

    if (assetIds.length == 0) revert EmptyBatch();
    if (assetIds.length > MAX_BATCH_SIZE) {
        revert BatchTooLarge(assetIds.length, MAX_BATCH_SIZE);
    }

    // Require active epoch with finalized VRF
    if (activeEpoch == 0) revert VRFNotReady();
    Epoch storage epoch = epochs[activeEpoch];
    // V3.3.5 FIX: Removed "epoch.randomSeed == 0" check - seed 0 is valid!
    // Only check fulfilled flag (V3.3.4) and finalization status
    if (!epoch.fulfilled) revert VRFNotReady();
    if (!epochFinalized[activeEpoch]) revert VRFNotReady(); // Must be finalized

    // Fetch batch asset info from JJSKIN
    (
        uint56[] memory prices,
        uint40[] memory purchaseTimes,
        IJJSKIN.PurchaseStatus[] memory statuses
    ) = IJJSKIN(jjskin).getBatchAssetInfo(assetIds);

    uint256 _deliveryWindow = IJJSKIN(jjskin).deliveryWindow();

    // Calculate total value and validate each asset
    uint256 totalValue = 0;
    for (uint256 i = 0; i < assetIds.length; i++) {
        uint64 assetId = assetIds[i];

        if (statuses[i] != IJJSKIN.PurchaseStatus.Active) {
            revert AssetNotPending(assetId);
        }

        uint256 readyAt = purchaseTimes[i] + _deliveryWindow;
        if (block.timestamp < readyAt) {
            revert AssetNotReady(assetId, readyAt);
        }

        if (settledAssets[assetId]) {
            revert AssetAlreadySettled(assetId);
        }

        bytes32 existingBatch = pendingAssets[assetId];
        if (existingBatch != bytes32(0)) {
            revert AssetInPendingBatch(assetId, existingBatch);
        }

        totalValue += prices[i];
    }

    // Check batch cap (based on selection stake snapshot)
    uint256 cap = getBatchCap();
    if (totalValue > cap) revert BatchCapExceeded(totalValue, cap);

    // V3.3.2 FIX: Check absolute batch value ceiling (bucket model constraint)
    // minStake = 0.3 * totalValue must fit within bucket range
    if (totalValue > MAX_BATCH_VALUE) revert BatchValueTooHigh(totalValue, MAX_BATCH_VALUE);

    // V3.2 FIX: LIVENESS CHECK with EFFECTIVE minStake (bucket-snapped)
    uint256 minStakeRaw = _getMinStake(totalValue);
    uint8 minBucket = _getMinBucket(minStakeRaw);
    uint256 eligibleCount = eligibleCountFromBucket[minBucket];
    if (eligibleCount < QUORUM + 1) {
        revert InsufficientEligibleVerifiers(eligibleCount, QUORUM + 1);
    }

    // Pull deposit from creator
    usdc.safeTransferFrom(msg.sender, address(this), batchDeposit);

    // V3.2 FIX: Generate unique batch ID with nonce (prevents collision)
    batchId = keccak256(abi.encode(assetIds, arweaveBlock, block.number, msg.sender, batchNonce++));

    // V3.2 FIX: Collision check (belt and suspenders)
    if (batches[batchId].createdAt != 0) revert BatchIdCollision();

    // Mark assets as pending
    for (uint256 i = 0; i < assetIds.length; i++) {
        pendingAssets[assetIds[i]] = batchId;
    }

    // Create batch (NO verifier assignment - self-selection at commit)
    Batch storage batch = batches[batchId];
    batch.assetIds = assetIds;
    batch.totalValue = uint128(totalValue);
    batch.creatorDeposit = uint128(batchDeposit);
    batch.commitDeadline = uint40(block.timestamp + COMMIT_WINDOW);
    batch.revealDeadline = uint40(block.timestamp + COMMIT_WINDOW + REVEAL_WINDOW);
    batch.createdAt = uint40(block.timestamp);
    batch.state = BatchState.COMMIT_PHASE;
    batch.currentRound = 0;
    batch.creator = msg.sender;
    batch.arweaveBlock = arweaveBlock;
    batch.batchEpoch = activeEpoch;  // Lock to current epoch for selection
    batch.createdEntropy = bytes32(block.prevrandao);  // V3.3: Store entropy at creation (avoids 256-block staleness)

    // Track batch in epoch for retrospective audit
    epochBatches[activeEpoch].push(batchId);

    emit ArweaveBatchCreated(batchId, assetIds, arweaveBlock, totalValue, msg.sender);
}

/**
 * @notice Dynamic batch cap based on selection stake snapshot
 * @dev V2: Cap = totalSelectionStake / α where α = 1.5 (security margin)
 *      This ensures there's enough slashable stake to cover batch value
 */
function getBatchCap() public view returns (uint256) {
    if (totalSelectionStake == 0) return 0;

    // V_max = totalSelectionStake / 1.5 = totalSelectionStake × 10000 / 15000
    return (totalSelectionStake * BPS) / SECURITY_MARGIN_BPS;
}
```

---

## Part 9: Modified submitCommit (VerifierNetwork.sol)

Replace the function (around line 1051):

```solidity
// V3.3.5: Error for stale epoch batches
error StaleEpochBatch(bytes32 batchId, uint256 batchEpoch, uint256 currentEpoch);

/**
 * @notice Submit commitment hash for per-asset decisions
 * @dev V2 Changes:
 *      - Self-selection via _isSelected() (uses selection snapshot)
 *      - ONE PARTICIPATION PER BATCH: Cannot commit to multiple rounds
 *      - Commit hash includes round: keccak256(batchId, round, decisions, salt)
 *      - Audit freshness enforced here (not at batch creation)
 *      - BLOCKED during epoch transition (rebuild in progress)
 *      - V3.3.5: BLOCKED if batch is from stale epoch
 *
 * @param batchId Batch to vote on
 * @param commitHash keccak256(abi.encode(batchId, round, decisions, salt))
 */
function submitCommit(bytes32 batchId, bytes32 commitHash) external {
    // EPOCH TRANSITION PAUSE: Cannot commit during rebuild
    // This prevents reads of partially-overwritten snapshot
    if (_isEpochTransitioning()) revert EpochTransitioning();

    Batch storage batch = batches[batchId];

    // V3.3.5 FIX: Reject commits for batches from old epochs
    // After epoch transition, snapshot was overwritten - selection would be inconsistent
    // This prevents accepting commits that would succeed with wrong committee
    if (batch.batchEpoch != activeEpoch) {
        revert StaleEpochBatch(batchId, batch.batchEpoch, activeEpoch);
    }

    // Poke to ensure correct state
    BatchState state = _poke(batchId);

    if (state != BatchState.COMMIT_PHASE) {
        revert InvalidBatchState(state, BatchState.COMMIT_PHASE);
    }

    // Must be active verifier
    Verifier storage v = verifiers[msg.sender];
    if (!v.isActive) revert NotActiveVerifier();

    // ONE PARTICIPATION PER BATCH: Check if already committed to ANY round
    if (committedRoundPlus1[batchId][msg.sender] != 0) {
        revert AlreadyCommitted();
    }

    // Self-selection check (uses epoch-locked selection stake)
    uint8 round = batch.currentRound;
    if (!_isSelected(batchId, round, msg.sender)) {
        revert NotSelectedVerifier();
    }

    // AUDIT FRESHNESS: For audit batches, cannot have participated in original
    if (batch.isAuditBatch) {
        bytes32 originalBatchId = auditBatchMeta[batchId].originalBatchId;

        // Cannot have committed to original batch (any round)
        if (committedRoundPlus1[originalBatchId][msg.sender] != 0) {
            revert InvalidInput(); // "Committed on original"
        }

        // Cannot have revealed on original batch (any round)
        if (revealedRoundPlus1[originalBatchId][msg.sender] != 0) {
            revert InvalidInput(); // "Revealed on original"
        }
    }

    // Record commitment
    commits[batchId][msg.sender] = commitHash;
    committedRoundPlus1[batchId][msg.sender] = round + 1;
    roundCommitters[batchId][round].push(msg.sender);

    // V3.3.3 FIX: Store the reveal deadline for this round
    // This ensures slashNoReveal uses the correct deadline even after batch retries
    if (roundRevealDeadline[batchId][round] == 0) {
        roundRevealDeadline[batchId][round] = batch.revealDeadline;
    }

    emit CommitSubmitted(batchId, msg.sender);
}
```

---

## Part 10: Modified submitReveal (VerifierNetwork.sol)

Replace the function (around line 1079):

```solidity
/**
 * @notice Reveal per-asset decisions
 * @dev V2 Changes:
 *      - Per-round vote tracking for retry consensus
 *      - Commit hash includes round (prevents cross-round replay)
 *      - totalVotes += decisions.length (per-asset tracking)
 *
 * @param batchId Batch ID
 * @param decisions Array of AssetDecision (must cover all assets)
 * @param salt Random salt used in commitment
 */
function submitReveal(
    bytes32 batchId,
    AssetDecision[] calldata decisions,
    bytes32 salt
) external nonReentrant {  // V3.3.6 FIX: Added nonReentrant (calls external JJSKIN contract)
    // Poke to ensure correct state
    BatchState state = _poke(batchId);

    Batch storage batch = batches[batchId];
    if (state != BatchState.REVEAL_PHASE) {
        revert InvalidBatchState(state, BatchState.REVEAL_PHASE);
    }

    uint8 round = batch.currentRound;

    // Must have committed THIS round (one participation per batch)
    uint8 commitRound = committedRoundPlus1[batchId][msg.sender];
    if (commitRound != round + 1) {
        revert CommitHashMismatch(); // Didn't commit this round (or committed different round)
    }

    // Cannot reveal twice
    if (revealedRoundPlus1[batchId][msg.sender] != 0) {
        revert AlreadyRevealed();
    }

    // Must have one decision per asset
    if (decisions.length != batch.assetIds.length) {
        revert DecisionCountMismatch(decisions.length, batch.assetIds.length);
    }

    // Verify commitment (hash includes round for replay protection)
    bytes32 expectedHash = keccak256(abi.encode(batchId, round, decisions, salt));
    if (commits[batchId][msg.sender] != expectedHash) {
        revert CommitHashMismatch();
    }

    Verifier storage v = verifiers[msg.sender];

    // Record reveal
    revealedRoundPlus1[batchId][msg.sender] = round + 1;
    hasRevealed[batchId][msg.sender] = true; // Legacy compatibility
    batchVoters[batchId].push(msg.sender);   // No duplicates: one participation per batch
    batch.revealCount++;
    v.assignedBatches++;  // Track participation
    v.totalVotes += decisions.length;  // Per-asset vote tracking

    // Record per-asset, per-round votes
    for (uint256 i = 0; i < decisions.length; i++) {
        AssetDecision calldata d = decisions[i];

        if (d.assetId != batch.assetIds[i]) {
            revert InvalidAssetId(d.assetId);
        }

        // Store vote (no overwrites: one participation per batch)
        assetVotes[batchId][d.assetId][msg.sender] = d;

        // Update per-round vote counts (for this round's consensus check)
        assetVoteCountsR[batchId][round][d.assetId][d.decision]++;

        // Legacy vote counts (for backward compatibility / slashing)
        assetVoteCounts[batchId][d.assetId][d.decision]++;

        if (d.decision == Decision.REFUND) {
            assetRefundReasonCountsR[batchId][round][d.assetId][d.refundReason]++;
            assetRefundReasonCounts[batchId][d.assetId][d.refundReason]++;
        }

        emit AssetVoteRecorded(batchId, d.assetId, msg.sender, d.decision);
    }

    emit RevealSubmitted(batchId, msg.sender, decisions.length);

    // Try auto-execute for this round
    _tryAutoExecuteRound(batchId, round);
}
```

---

## Part 11: Modified VRF Functions (VerifierNetwork.sol)

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// VRF INTEGRATION (O(1) callback + chunked finalization)
// ═══════════════════════════════════════════════════════════════════════════

// V3.3 error
error EpochTooSoon();

/**
 * @notice Start a new epoch and request VRF randomness
 * @dev Single pending epoch gating: Only one pending request at a time
 *      This prevents DoS via epoch spam
 *      V3.3 FIX: Rate limiting via EPOCH_MIN_INTERVAL
 *      V3.3.4 FIX: Use epochNonce for unique epoch IDs (prevents ID reuse after cancel)
 *      V3.3.5 FIX: Require bond to prevent permissionless VRF subscription drain
 */
function startNewEpoch() external nonReentrant {
    if (s_subscriptionId == 0) revert InvalidInput();

    // SINGLE PENDING EPOCH: Cannot request new epoch while one is pending
    if (pendingEpoch != 0) revert InvalidInput(); // "Epoch already pending"

    // Also cannot request if previous epoch isn't finalized yet
    if (activeEpoch > 0 && !epochFinalized[activeEpoch]) revert InvalidInput();

    // V3.3 FIX: Rate limiting - prevent epoch spam DoS
    // Cannot start new epoch within EPOCH_MIN_INTERVAL of previous start
    if (block.timestamp < lastEpochStartTime + EPOCH_MIN_INTERVAL) revert EpochTooSoon();

    // V3.3.5 FIX: Require epoch-starter bond to prevent VRF subscription drain
    // Bond is returned on successful finalization, slashed on cancel
    // This ensures the epoch starter has skin in the game to see it through
    usdc.safeTransferFrom(msg.sender, address(this), EPOCH_STARTER_BOND);
    epochStarter = msg.sender;

    // V3.3.4 FIX: Use monotonic epochNonce for epoch ID instead of activeEpoch + 1
    // This prevents epoch ID reuse after cancelStaleEpoch()
    // Old: pendingEpoch = activeEpoch + 1; // BUG: After cancel, same ID could be reused
    pendingEpoch = ++epochNonce;

    // V3.3.5: Store bond for this epoch
    epochStarterBonds[pendingEpoch] = EPOCH_STARTER_BOND;

    // V3.3: Update rate limit timestamp
    lastEpochStartTime = block.timestamp;

    uint256 requestId = s_vrfCoordinator.requestRandomWords(
        VRFV2PlusClient.RandomWordsRequest({
            keyHash: s_keyHash,
            subId: s_subscriptionId,
            requestConfirmations: s_requestConfirmations,
            callbackGasLimit: s_callbackGasLimit,
            numWords: 1,
            extraArgs: VRFV2PlusClient._argsToBytes(
                VRFV2PlusClient.ExtraArgsV1({nativePayment: false})
            )
        })
    );

    epochs[pendingEpoch] = Epoch({
        vrfRequestId: requestId,
        randomSeed: 0,
        startTime: uint40(block.timestamp),
        fulfilled: false
    });

    vrfRequestToEpoch[requestId] = pendingEpoch;

    emit EpochStarted(pendingEpoch, requestId);
}

/**
 * @notice VRF callback - called by Chainlink VRF Coordinator
 * @dev V3.3.5: Pure O(1) callback - REMOVED auto-finalize for safety
 *      Auto-finalize (V3.3.2) was risky: callback gas is limited and unpredictable,
 *      could revert if verifier list grows during VRF latency.
 *      With epoch-starter bond, the starter has incentive to finalize.
 *      V3.3.3: Added epoch==0 defense for edge case protection
 *      V3.3.4: Added vrfRequestId check to prevent epoch ID reuse attack
 */
function fulfillRandomWords(
    uint256 requestId,
    uint256[] calldata randomWords
) internal override {
    uint256 epoch = vrfRequestToEpoch[requestId];

    // V3.3.3 FIX: Reject epoch 0 as defense against mapping default value
    // vrfRequestToEpoch[unknownRequestId] returns 0, which could match epoch 0
    // This should never happen in practice (epochs start at 1), but defense-in-depth
    if (epoch == 0) return;

    // Ignore stale fulfillments
    if (epoch != pendingEpoch) return;

    Epoch storage e = epochs[epoch];

    // V3.3.4 FIX: Verify requestId matches what we stored at epoch creation
    // Prevents epoch ID reuse attack after cancelStaleEpoch():
    // 1. Epoch 5 created with requestId=100
    // 2. VRF times out, cancelStaleEpoch() clears pendingEpoch
    // 3. New epoch 6 created (via epochNonce), but vrfRequestToEpoch[100] still points to 5
    // 4. If VRF later fulfills requestId=100, epoch=5 but pendingEpoch=6
    // The `epoch != pendingEpoch` check handles this, but belt-and-suspenders:
    if (e.vrfRequestId != requestId) return;

    e.randomSeed = randomWords[0];
    e.fulfilled = true;

    // V3.3.4: Track fulfillment time for EPOCH_FINALIZE_TIMEOUT escape hatch
    epochFulfilledAt[epoch] = uint40(block.timestamp);

    // V3.3.5: Removed auto-finalize (was V3.3.2)
    // - Auto-finalize was risky: if verifier list grows during VRF latency, callback reverts
    // - Callback gas limit is fixed at request time, can't adapt to larger lists
    // - With epoch-starter bond (V3.3.5), starter has incentive to call finalizeEpochChunk()
    // - EPOCH_FINALIZE_TIMEOUT escape hatch protects against stuck epochs
    //
    // Snapshot rolling happens in permissionless finalizeEpochChunk() calls
    // pendingEpoch stays set until finalization completes

    emit EpochFulfilled(epoch, new address[](0));
}

// V3.3.5: DELETED _autoFinalizeSmallEpoch() - see fulfillRandomWords comment above
// The epoch-starter bond + EPOCH_FINALIZE_TIMEOUT escape hatch replaces this pattern
```

---

## Part 12: Modified Staking Functions (VerifierNetwork.sol)

**CRITICAL**:
- Staking functions do NOT update selection buckets (voluntary changes)
- Unbonded stake remains slashable until `claimUnbonding()`
- `stakedAmount` is NOT reduced during unbonding period

```solidity
/**
 * @notice Register as a verifier with stake
 * @dev V2: Does NOT update selection buckets (snapshot at epoch finalization)
 *      BLOCKED when stake is frozen (VRF fulfilled but not finalized)
 */
function registerVerifier(uint256 amount) external nonReentrant {
    // STAKE FREEZE: Cannot register after VRF seed is revealed
    // This prevents grinding via new registrations after seeing seed
    if (_isStakeFrozen()) revert StakeFrozen();

    if (verifiers[msg.sender].isActive) revert AlreadyRegistered();
    if (amount < MIN_STAKE) revert InsufficientStake(amount, MIN_STAKE);

    // V3.3.5 FIX: Bucket-aware concentration check (replaces V3.3.4 global percentage)
    // Checks all bucket tiers to prevent selection saturation at any eligibility level
    _checkConcentration(msg.sender, amount);

    usdc.safeTransferFrom(msg.sender, address(this), amount);

    // Initialize verifier (selectionStake = 0 until next epoch finalization)
    verifiers[msg.sender] = Verifier({
        stakedAmount: amount,
        selectionStake: 0,  // Will be set at next epoch finalization
        unbondingAmount: 0,
        pendingRewards: 0,
        minorityVotes: 0,
        totalVotes: 0,
        assignedBatches: 0,
        registeredAt: uint40(block.timestamp),
        lastSlashTime: 0,
        unbondingStart: 0,
        minorityWarnings: 0,
        participationWarnings: 0,
        isActive: true
    });

    // Add to active list
    verifierIndex[msg.sender] = activeVerifierList.length;
    activeVerifierList.push(msg.sender);
    activeVerifierCount++;
    totalStake += amount;

    // NOTE: No bucket update - selection snapshot at epoch finalization

    emit VerifierRegistered(msg.sender, amount);
}

/**
 * @notice Add more stake to existing registration
 * @dev V2: Does NOT update selection buckets (snapshot at epoch finalization)
 *      BLOCKED when stake is frozen (VRF fulfilled but not finalized)
 */
function addStake(uint256 amount) external nonReentrant {
    // STAKE FREEZE: Cannot add stake after VRF seed is revealed
    if (_isStakeFrozen()) revert StakeFrozen();

    Verifier storage v = verifiers[msg.sender];
    if (!v.isActive) revert NotActiveVerifier();

    uint256 newStake = v.stakedAmount + amount;

    // V3.3.5 FIX: Bucket-aware concentration check (replaces V3.3.4 global percentage)
    _checkConcentration(msg.sender, newStake);

    usdc.safeTransferFrom(msg.sender, address(this), amount);

    v.stakedAmount = newStake;
    totalStake += amount;

    // NOTE: No bucket update - selection snapshot at epoch finalization

    emit VerifierStakeUpdated(msg.sender, newStake);
}

/**
 * @notice Initiate unstaking with 28-day cooldown
 * @dev V2: stakedAmount is NOT reduced - stake remains slashable until claim
 *      This ensures selectionStake <= slashable stake always
 *      BLOCKED when stake is frozen (VRF fulfilled but not finalized)
 */
function initiateUnbonding(uint256 amount) external nonReentrant {
    // STAKE FREEZE: Cannot unbond after VRF seed is revealed
    if (_isStakeFrozen()) revert StakeFrozen();

    Verifier storage v = verifiers[msg.sender];
    if (!v.isActive) revert NotActiveVerifier();
    if (amount > v.stakedAmount) revert InsufficientStake(v.stakedAmount, amount);
    if (v.unbondingAmount > 0) revert UnbondingInProgress();

    uint256 remaining = v.stakedAmount - amount;
    if (remaining > 0 && remaining < MIN_STAKE) {
        revert InsufficientStake(remaining, MIN_STAKE);
    }

    // DO NOT reduce stakedAmount - keep stake slashable during unbonding
    // v.stakedAmount -= amount; // REMOVED
    v.unbondingAmount = amount;
    v.unbondingStart = uint40(block.timestamp);
    // totalStake -= amount; // REMOVED - stake still counts

    // NOTE: No bucket update - selection snapshot at epoch finalization
    // NOTE: selectionStake unchanged - but stake is still slashable

    if (remaining == 0) {
        // Fully unbonding - deactivate but keep stake slashable
        v.isActive = false;
        activeVerifierCount--;
        _removeFromActiveList(msg.sender);

        // Update selection snapshot (deactivation is a forced change)
        _removeFromSelectionSnapshot(msg.sender);
    }

    emit UnbondingInitiated(msg.sender, amount, uint40(block.timestamp + UNBONDING_PERIOD));
}

/**
 * @notice Claim unbonded stake after cooldown
 * @dev V2: NOW reduces stakedAmount and totalStake
 *      V3.3.1: Clamps selectionStake if it exceeds new stakedAmount
 *      BLOCKED when stake is frozen (VRF fulfilled but not finalized)
 */
function claimUnbonding() external nonReentrant {
    // STAKE FREEZE: Cannot claim after VRF seed is revealed
    if (_isStakeFrozen()) revert StakeFrozen();

    Verifier storage v = verifiers[msg.sender];
    if (v.unbondingAmount == 0) revert NoUnbondingRequest();
    if (block.timestamp < v.unbondingStart + UNBONDING_PERIOD) revert CooldownNotComplete();
    if (block.timestamp > v.unbondingStart + UNBONDING_PERIOD + CLAIM_WINDOW) revert ClaimWindowExpired();

    uint256 amount = v.unbondingAmount;

    // NOW reduce stakedAmount and totalStake
    v.stakedAmount -= amount;
    totalStake -= amount;
    v.unbondingAmount = 0;
    v.unbondingStart = 0;

    // V3.3.1 FIX: Clamp selectionStake if it now exceeds slashable stake
    // This preserves "snapshot never exceeds slashable" invariant
    if (v.selectionStake > v.stakedAmount) {
        _updateSelectionStake(msg.sender, v.stakedAmount);
    }

    usdc.safeTransfer(msg.sender, amount);

    emit UnbondingClaimed(msg.sender, amount);
}

/**
 * @notice Cancel unbonding and return to active staking
 * @dev BLOCKED when stake is frozen (VRF fulfilled but not finalized)
 */
function cancelUnbonding() external nonReentrant {
    // STAKE FREEZE: Cannot cancel unbonding after VRF seed is revealed
    if (_isStakeFrozen()) revert StakeFrozen();

    Verifier storage v = verifiers[msg.sender];
    if (v.unbondingAmount == 0) revert NoUnbondingRequest();

    uint256 amount = v.unbondingAmount;
    v.unbondingAmount = 0;
    v.unbondingStart = 0;

    // If was deactivated due to full unbond, reactivate
    if (!v.isActive && v.stakedAmount >= MIN_STAKE) {
        v.isActive = true;
        activeVerifierCount++;
        _addToActiveList(msg.sender);
        // Selection snapshot will be updated at next epoch finalization
    }

    emit UnbondingCancelled(msg.sender, amount);
}
```

---

## Part 13: Modified Slashing Functions (VerifierNetwork.sol)

**CRITICAL**: Slashing is a forced change that MUST update selection snapshot

**V3.3 FIX**: Block forced changes during snapshot rebuild to prevent:
1. Swap-pop corruption of activeVerifierList during iteration
2. Stale stake data in Next arrays after already-processed verifiers are slashed

**V3.3.3 FIX**: Allow slashing during rebuild with delta corrections:
1. Track which verifiers were snapshotted via `selectionEpochTag[verifier] = epochId`
2. If slashing a verifier that's already in Next arrays, apply delta correction
3. Suspension still blocked (swap-pop breaks iteration), but slashing is the critical path

```solidity
// V3.3 error (kept for _suspendVerifier)
error RebuildInProgress();

/**
 * @notice Apply delta correction to Next snapshot arrays
 * @dev V3.3.3: Called when slashing a verifier already processed into Next
 * @param verifierAddr The verifier being slashed
 * @param oldStake The verifier's stake when snapshotted into Next
 * @param newStake The verifier's stake after slashing
 */
function _applyNextSnapshotDelta(address verifierAddr, uint256 oldStake, uint256 newStake) internal {
    // Remove old stake contribution from Next arrays
    if (oldStake >= BUCKET_BASE) {
        uint8 oldBucket = _getBucket(oldStake);
        bucketStakeSumNext[oldBucket] -= oldStake;
        bucketCountNext[oldBucket]--;
    }
    totalSelectionStakeNext -= oldStake;
    totalSelectionCountNext--;

    // Add new stake contribution to Next arrays
    if (newStake >= BUCKET_BASE) {
        uint8 newBucket = _getBucket(newStake);
        bucketStakeSumNext[newBucket] += newStake;
        bucketCountNext[newBucket]++;
    }
    if (newStake > 0) {
        totalSelectionStakeNext += newStake;
        totalSelectionCountNext++;
    }
}

/**
 * @notice Slash a verifier's stake
 * @dev V2: Updates selection snapshot immediately (forced change)
 *      Slash applies to full stakedAmount (includes unbonding portion)
 *      V3.3.3 FIX: Uses delta corrections during rebuild instead of reverting
 */
function _slashVerifier(address verifierAddr, uint256 amount, string memory reason) internal {
    Verifier storage v = verifiers[verifierAddr];

    // Slash from stakedAmount (includes unbonding portion - still slashable!)
    uint256 slashable = v.stakedAmount;
    uint256 actualSlash = amount > slashable ? slashable : amount;

    if (actualSlash == 0) return;

    // Store old selectionStake for delta correction
    uint256 oldSelectionStake = v.selectionStake;

    v.stakedAmount -= actualSlash;
    totalStake -= actualSlash;

    // If unbonding, reduce unbondingAmount proportionally
    if (v.unbondingAmount > 0) {
        uint256 unbondingSlash = (actualSlash * v.unbondingAmount) / slashable;
        v.unbondingAmount -= unbondingSlash;
    }

    // V3.3.3 FIX: Handle slashing during rebuild with delta corrections
    if (_isSnapshotRebuilding()) {
        // Check if this verifier was already processed into Next arrays
        if (selectionEpochTag[verifierAddr] == pendingEpoch) {
            // Already in Next - apply delta correction
            uint256 newSelectionStake = v.stakedAmount;
            _applyNextSnapshotDelta(verifierAddr, oldSelectionStake, newSelectionStake);
            v.selectionStake = newSelectionStake;
        }
        // If not yet processed (selectionEpochTag != pendingEpoch), the chunk loop
        // will pick up the new stakedAmount when it reaches this verifier
    } else {
        // Normal case: update selection snapshot immediately
        _updateSelectionStake(verifierAddr, v.stakedAmount);
    }

    // Add to slashing treasury
    slashingTreasury += actualSlash;

    v.lastSlashTime = uint40(block.timestamp);

    // Check if should deactivate
    // V3.3.3: Suspension still blocked during rebuild (swap-pop issue)
    // V3.3.6 FIX: Actually set needsSuspension flag (was missing in V3.3.4)
    if (v.stakedAmount < MIN_STAKE && v.isActive) {
        if (_isSnapshotRebuilding()) {
            // During rebuild, we can't suspend (swap-pop breaks iteration)
            // The verifier stays active with insufficient stake until rebuild completes
            // This is safe: they're already slashed, and will be suspended after rebuild
            needsSuspension[verifierAddr] = true;  // V3.3.6 FIX: Must set flag!
            emit SuspensionDeferred(verifierAddr, "Insufficient stake after slash");
        } else {
            _suspendVerifier(verifierAddr, reason);
        }
    }

    emit VerifierSlashed(verifierAddr, actualSlash, reason);
}

// V3.3.3 event for deferred suspension
event SuspensionDeferred(address indexed verifier, string reason);

/**
 * @notice Suspend a verifier (deactivate)
 * @dev V2: Updates selection snapshot immediately (forced change)
 *      V3.3 FIX: Reverts during rebuild to prevent swap-pop iteration corruption
 *      V3.3.4 FIX: Defer suspension during rebuild (mark for later processing)
 */
function _suspendVerifier(address verifierAddr, string memory reason) internal {
    // V3.3.4 FIX: Defer suspension during rebuild instead of reverting
    // Old (V3.3): if (_isSnapshotRebuilding()) revert RebuildInProgress();
    if (_isSnapshotRebuilding()) {
        needsSuspension[verifierAddr] = true;
        emit SuspensionDeferred(verifierAddr, reason);
        return;  // Will be processed after rebuild completes
    }

    Verifier storage v = verifiers[verifierAddr];

    if (!v.isActive) return;

    v.isActive = false;
    activeVerifierCount--;
    _removeFromActiveList(verifierAddr);

    // FORCED CHANGE: Remove from selection snapshot immediately
    _removeFromSelectionSnapshot(verifierAddr);

    emit VerifierSuspended(verifierAddr, reason);
}

/**
 * @notice Process a deferred suspension after rebuild completes (V3.3.4)
 * @dev Permissionless - anyone can call to complete deferred suspensions
 *      MUST be called after rebuild completes (pendingEpoch == 0)
 *      Processes one verifier at a time to avoid gas issues
 */
function processSuspension(address verifierAddr) external {
    // Cannot process during rebuild
    if (_isSnapshotRebuilding()) revert RebuildInProgress();

    // Must have deferred suspension pending
    if (!needsSuspension[verifierAddr]) revert InvalidInput(); // "No deferred suspension"

    // Clear the flag first (reentrancy safe)
    needsSuspension[verifierAddr] = false;

    Verifier storage v = verifiers[verifierAddr];

    // May have already been suspended by other means
    if (!v.isActive) return;

    v.isActive = false;
    activeVerifierCount--;
    _removeFromActiveList(verifierAddr);
    _removeFromSelectionSnapshot(verifierAddr);

    emit VerifierSuspended(verifierAddr, "Deferred suspension processed");
}

// V3.3.4 event
event DeferredSuspensionProcessed(address indexed verifier);

// ═══════════════════════════════════════════════════════════════════════════
// V3.2: EXPLICIT SLASH-NO-REVEAL ENFORCEMENT
// V3.3.3: Per-round reveal deadlines for accurate slashing
// ═══════════════════════════════════════════════════════════════════════════

/// @notice Mapping to track if a verifier was already slashed for no-reveal on a batch
/// @dev batchId => verifier => slashed
mapping(bytes32 => mapping(address => bool)) public slashedForNoReveal;

// New errors for slashNoReveal
error NotCommitted();
error AlreadyRevealedForSlash();
error RevealWindowNotPassed();
error AlreadySlashedForNoReveal();

/**
 * @notice Slash a verifier who committed but failed to reveal
 * @dev Permissionless enforcement - anyone can call with proof
 *      V3.2: Concrete enforcement path for commit-no-reveal
 *
 *      V3.3.3 FIX: Uses per-round reveal deadlines instead of batch.revealDeadline
 *      PROBLEM: batch.revealDeadline changes on retry. If verifier commits in round 0,
 *      batch retries to round 1, and round 1's revealDeadline passes, the verifier
 *      could be incorrectly slashed (round 0 deadline was different).
 *
 *      SOLUTION: Store roundRevealDeadline[batchId][round] at commit time.
 *      Check against the deadline for the specific round the verifier committed to.
 *
 * @param batchId The batch where verifier committed but didn't reveal
 * @param verifierAddr The verifier to slash
 */
function slashNoReveal(bytes32 batchId, address verifierAddr) external nonReentrant {
    // Must have committed
    uint8 committedRound = committedRoundPlus1[batchId][verifierAddr];
    if (committedRound == 0) revert NotCommitted();
    uint8 round = committedRound - 1; // Convert from 1-indexed to 0-indexed

    // V3.3.3 FIX: Use per-round reveal deadline, not batch.revealDeadline
    // batch.revealDeadline is for the CURRENT round, which may have changed
    uint40 roundDeadline = roundRevealDeadline[batchId][round];
    if (block.timestamp <= roundDeadline) revert RevealWindowNotPassed();

    // Must NOT have revealed
    if (revealedRoundPlus1[batchId][verifierAddr] != 0) revert AlreadyRevealedForSlash();

    // Cannot slash twice for same batch
    if (slashedForNoReveal[batchId][verifierAddr]) revert AlreadySlashedForNoReveal();

    // Mark as slashed to prevent double-slash
    slashedForNoReveal[batchId][verifierAddr] = true;

    // Calculate slash amount (percentage of stake)
    Verifier storage v = verifiers[verifierAddr];
    uint256 slashAmount = (v.stakedAmount * NO_REVEAL_SLASH_BPS) / BPS;

    // Apply slash
    _slashVerifier(verifierAddr, slashAmount, "Commit without reveal");

    emit NoRevealSlash(batchId, verifierAddr, slashAmount);
}

// V3.2 event
event NoRevealSlash(bytes32 indexed batchId, address indexed verifier, uint256 amount);

// V3.2 constant (add to Part 1)
// uint256 public constant NO_REVEAL_SLASH_BPS = 1000; // 10% slash for no-reveal
```

---

## Part 14: DELETE Functions (VerifierNetwork.sol)

Remove these functions entirely:

1. `_assignVerifiersForBatch()` - Replaced by self-selection
2. `_isAssignedToBatch()` - No longer needed
3. `_tryAutoExecute()` - Replaced by `_tryAutoExecuteRound()`
4. `getThreshold()` public function - No longer used (QUORUM is constant)
5. `_rollSelectionSnapshot()` - Replaced by chunked `finalizeEpochChunk()`

---

## Part 15: VerifierNetworkExt.sol Changes

### Storage Layout Updates

Add these after existing storage (around line 197) - **MUST MATCH MAIN CONTRACT**:

```solidity
// ═══════════════════════════════════════════════════════════════════════════
// NEW STORAGE (must match VerifierNetwork exactly)
// ═══════════════════════════════════════════════════════════════════════════

uint256[14] public bucketStakeSumSel;
uint256[14] public bucketCountSel;
uint256 public totalSelectionStake;
uint256 public totalSelectionCount;

// Suffix sum caches for O(1) eligibility lookups (must match main contract)
uint256[14] public eligibleStakeFromBucket;
uint256[14] public eligibleCountFromBucket;

uint256 public activeEpoch;
uint256 public pendingEpoch;
mapping(uint256 => bool) public epochFinalized;
mapping(uint256 => uint256) public epochFinalizedUpTo;

mapping(bytes32 => mapping(address => uint8)) public committedRoundPlus1;
mapping(bytes32 => mapping(address => uint8)) public revealedRoundPlus1;
mapping(bytes32 => mapping(uint8 => address[])) public roundCommitters;
mapping(bytes32 => mapping(uint8 => mapping(uint64 => mapping(Decision => uint16)))) public assetVoteCountsR;
mapping(bytes32 => mapping(uint8 => mapping(uint64 => mapping(RefundReason => uint16)))) public assetRefundReasonCountsR;

// Next epoch arrays (built during finalization, must match main contract)
uint256[14] internal bucketStakeSumNext;
uint256[14] internal bucketCountNext;
uint256 internal totalSelectionStakeNext;
uint256 internal totalSelectionCountNext;

// V3.2: Batch collision prevention
uint256 public batchNonce;

// V3.2: No-reveal slashing
mapping(bytes32 => mapping(address => bool)) public slashedForNoReveal;

// V3.3: Finalizer rewards (pull pattern)
mapping(address => uint256) public finalizerRewards;

// V3.3: Epoch rate limiting
uint256 public lastEpochStartTime;

// V3.3.3: Rebuild-safe slashing support
mapping(address => uint256) internal selectionEpochTag;

// V3.3.3: Per-round reveal deadlines for accurate slashNoReveal
mapping(bytes32 => mapping(uint8 => uint40)) public roundRevealDeadline;

// V3.3.4: Epoch ID reuse prevention + deferred suspension (must match main contract)
uint256 public epochNonce;
mapping(address => bool) public needsSuspension;
mapping(uint256 => uint40) public epochFulfilledAt;
uint256 public auditBatchNonce;

// V3.3.5: Epoch starter bond (must match main contract)
address public epochStarter;
mapping(uint256 => uint256) public epochStarterBonds;
```

### Update Constants

Add to match main contract:

```solidity
uint256 public constant EXPECTED_COMMITTEE_SIZE = 7;
uint256 public constant TAU_ROUND_INCREMENT = 2;
uint256 public constant QUORUM = 5;
uint256 public constant MAX_ROUNDS = 3;
uint256 public constant MAX_BUCKETS = 14;
uint256 public constant BUCKET_BASE = MIN_STAKE;
uint256 public constant SECURITY_MARGIN_BPS = 15000;
uint256 public constant EPOCH_FINALIZE_CHUNK_SIZE = 50;
uint256 public constant EPOCH_VRF_TIMEOUT = 1 hours;
uint256 public constant EPOCH_MIN_INTERVAL = 4 hours;  // V3.3: Rate limiting
uint256 public constant EPOCH_FINALIZE_TIMEOUT = 6 hours;  // V3.3.4: Added back for escape hatch
uint256 public constant FINALIZE_CHUNK_REWARD = 1e6;  // V3.2
uint256 public constant NO_REVEAL_SLASH_BPS = 1000;   // V3.2
uint256 public constant MAX_BATCH_VALUE = 25_000_000e6;  // V3.3.2

// V3.3.5: Bucket-aware concentration constants (replaces MAX_STAKE_SHARE_BPS)
uint256 public constant TAU_MAX = 11;  // 7 + (3-1)*2 = 11 (rounds 0-indexed)
uint256 public constant CONCENTRATION_FACTOR = 2;  // 2x safety margin
uint256 public constant CONCENTRATION_ENFORCEMENT_MIN = 10;  // Bootstrap exception
uint256 public constant EPOCH_STARTER_BOND = 10e6;  // V3.3.5: 10 USDC bond

// New errors (must match main contract)
error EpochTransitioning();
error StakeFrozen();
error EpochNotStale();
error BatchValueTooHigh(uint256 value, uint256 max);  // V3.3.2
error BatchIdCollision();       // V3.2
error NotCommitted();           // V3.2
error AlreadyRevealedForSlash(); // V3.2
error RebuildInProgress();      // V3.3
error EpochTooSoon();           // V3.3
error NoRewardsToClaim();       // V3.3
error RevealWindowNotPassed();  // V3.2
error AlreadySlashedForNoReveal(); // V3.2
error StakeExceedsMax(uint256 requested, uint256 maxAllowed);  // V3.3.4/V3.3.5
error StaleEpochBatch(bytes32 batchId, uint256 batchEpoch, uint256 currentEpoch);  // V3.3.5
error OnlyEpochStarterCanBegin();  // V3.3.6
```

### Helper Functions (copy from main contract)

```solidity
// V3.3.4/V3.3.5: MUST match main contract exactly!
function _isEpochTransitioning() internal view returns (bool) {
    // V3.3.4 FIX: Narrowed from "pendingEpoch != 0" to rebuild-only
    // This allows batch/commit during VRF latency, blocks only during rebuild
    return _isSnapshotRebuilding();
}

function _isStakeFrozen() internal view returns (bool) {
    if (pendingEpoch == 0) return false;
    return epochs[pendingEpoch].fulfilled;
}

function _isSnapshotRebuilding() internal view returns (bool) {
    if (pendingEpoch == 0) return false;
    return epochFinalizedUpTo[pendingEpoch] > 0;
}

// V3.3.6: Bucket-aware concentration check (must match main contract)
// FIXED: Check only tightest tier (bucket k), not k..MAX_BUCKETS-1
function _checkConcentration(address verifier, uint256 newStake) internal view {
    if (activeVerifierCount < CONCENTRATION_ENFORCEMENT_MIN) return;

    uint8 k = _getBucket(newStake);
    uint256 eligible = eligibleStakeFromBucket[k];
    if (eligible == 0) return;

    uint256 maxAllowed = eligible / (TAU_MAX * CONCENTRATION_FACTOR);
    if (newStake > maxAllowed) revert StakeExceedsMax(newStake, maxAllowed);
}
```

### DELETE Functions

Remove these functions entirely:

1. `_selectVerifiersExcludingOriginal()` - Audit freshness at commit time
2. `_selectAllVerifiersForAudit()` - No longer needed
3. `_selectReplacementVerifiers()` - Replaced by per-round self-selection

### Modified _createAuditBatch

```solidity
function _createAuditBatch(
    bytes32 originalBatchId,
    uint64[] memory assetIds,
    address challenger,
    uint256 bond
) internal returns (bytes32 auditBatchId) {
    // V3.3.5 FIX: Block audit batch creation when VRF fulfilled (like normal batches)
    // Same reasoning: once seed is public, batch creator can grind batchId
    if (_isStakeFrozen()) revert StakeFrozen();

    Batch storage original = batches[originalBatchId];

    // V3.3.4 FIX: Add auditBatchNonce for collision prevention
    // Previously, same challenger + same assets + same block = collision
    auditBatchId = keccak256(abi.encode(
        "AUDIT",
        originalBatchId,
        assetIds,
        block.timestamp,
        challenger,
        auditBatchNonce++  // V3.3.4: Monotonic nonce prevents collision
    ));

    // V3.3.4 FIX: Collision check (belt-and-suspenders with nonce)
    if (batches[auditBatchId].createdAt != 0) revert BatchIdCollision();

    Batch storage auditBatch = batches[auditBatchId];
    auditBatch.assetIds = assetIds;
    auditBatch.totalValue = original.totalValue;
    auditBatch.creatorDeposit = uint128(bond);
    auditBatch.commitDeadline = uint40(block.timestamp + COMMIT_WINDOW);
    auditBatch.revealDeadline = uint40(block.timestamp + COMMIT_WINDOW + REVEAL_WINDOW);
    auditBatch.createdAt = uint40(block.timestamp);
    auditBatch.state = BatchState.COMMIT_PHASE;
    auditBatch.currentRound = 0;
    auditBatch.isAuditBatch = true;
    auditBatch.creator = msg.sender;
    auditBatch.batchEpoch = activeEpoch;  // Use current active epoch

    // V3.3.4 FIX: Set createdEntropy for anti-grinding (same as normal batches)
    // Previously audit batches had no createdEntropy, allowing grinding via 256-block staleness
    auditBatch.createdEntropy = bytes32(block.prevrandao);

    auditBatchMeta[auditBatchId] = AuditBatchMeta({
        originalBatchId: originalBatchId,
        challenger: challenger
    });

    // NO verifier selection - self-selection at commit time
    // Freshness enforced in submitCommit() via committedRoundPlus1/revealedRoundPlus1

    return auditBatchId;
}
```

### Modified retryBatchSelection

```solidity
function retryBatchSelection(bytes32 batchId) external nonReentrant {
    Batch storage batch = batches[batchId];

    // Poke to ensure correct state (handles time-based transitions)
    if (batch.state == BatchState.COMMIT_PHASE && block.timestamp > batch.commitDeadline) {
        uint256 commitCount = roundCommitters[batchId][batch.currentRound].length;
        if (commitCount == 0) {
            batch.state = BatchState.READY;
        } else {
            batch.state = BatchState.REVEAL_PHASE;
        }
    }
    if (batch.state == BatchState.REVEAL_PHASE && block.timestamp > batch.revealDeadline) {
        batch.state = BatchState.READY;
    }

    if (batch.state != BatchState.READY) {
        revert InvalidBatchState(batch.state, BatchState.READY);
    }

    // Check if all assets have consensus already
    bool allHaveConsensus = true;
    for (uint256 i = 0; i < batch.assetIds.length; i++) {
        if (!assetConsensus[batchId][batch.assetIds[i]].hasConsensus) {
            allHaveConsensus = false;
            break;
        }
    }
    if (allHaveConsensus) revert RetryNotNeeded();

    // Check timeout
    if (block.timestamp > batch.createdAt + BATCH_FAILURE_TIMEOUT) {
        _handleBatchFailure(batchId);
        return;
    }

    // Open next round (or fail if max rounds exceeded)
    _openNextRoundOrFail(batchId);
}

/**
 * @notice Open next retry round or fail the batch
 * @dev Copied from main contract for extension access
 *      CRITICAL: Fails batches from old epochs (single snapshot constraint)
 */
function _openNextRoundOrFail(bytes32 batchId) internal {
    Batch storage batch = batches[batchId];

    // EPOCH-BOUND CHECK: Cannot retry batches from old epochs
    // Single snapshot was overwritten - selection would be inconsistent
    if (batch.batchEpoch != activeEpoch) {
        _handleBatchFailure(batchId);
        emit StaleEpochBatchFailed(batchId, batch.batchEpoch, activeEpoch);
        return;
    }

    if (batch.currentRound >= MAX_ROUNDS - 1) {
        _handleBatchFailure(batchId);
        return;
    }

    batch.currentRound++;
    batch.revealCount = 0;
    batch.commitDeadline = uint40(block.timestamp + COMMIT_WINDOW);
    batch.revealDeadline = uint40(block.timestamp + COMMIT_WINDOW + REVEAL_WINDOW);
    batch.state = BatchState.COMMIT_PHASE;

    emit BatchRetried(batchId, batch.currentRound, new address[](0));
}

// New event (must match main contract)
event StaleEpochBatchFailed(bytes32 indexed batchId, uint256 batchEpoch, uint256 activeEpoch);
```

---

## Summary of All Correctness Fixes

| Issue | Root Cause | Fix Applied |
|-------|------------|-------------|
| VRF callback gas limit | `_rollSelectionSnapshot()` O(n) in callback | O(1) callback, chunked `finalizeEpochChunk()` |
| Forced changes stale snapshot | Slash/suspend didn't update buckets | `_updateSelectionStake()` and `_removeFromSelectionSnapshot()` on forced changes |
| No liveness guarantee | No check for eligible verifiers | `bucketCountSel[]` + `eligibleCount >= QUORUM + 1` check |
| Retry liveness | Prior participants excluded, τ constant | Dynamic τ: `τ_round = τ + round * 2` |
| Unbonding stake mismatch | `stakedAmount` reduced, `selectionStake` exceeded slashable | Unbonded stake slashable until claim |
| Grinding via live buckets | `_getEligibleStake()` used live buckets | Selection-only buckets, updated at epoch finalization |
| Epoch DoS | Could spam `startNewEpoch()` | Single pending epoch gating |
| Bucket/stake mismatch | `BUCKET_BASE = 1e6` vs `MIN_STAKE = 1000e6` | `BUCKET_BASE = MIN_STAKE` |
| Retry overwrites votes | Same verifier multi-round commit | One participation per batch |
| Wasted reveal window | Always waited full reveal | Early READY on 0 commits |
| Cap formula | Used old threshold | `V_max = totalSelectionStake / 1.5` |
| **Snapshot corruption** | Old batches read snapshot being overwritten | Epoch transition pause (block batch/commit when `pendingEpoch != 0`) |
| **Post-seed grinding** | Stake changes after VRF seed visible | Stake freeze when `pendingEpoch != 0 && fulfilled` |
| **Stale epoch finalization** | Could finalize wrong epochId | Require `epochId == pendingEpoch` in `finalizeEpochChunk()` |
| **Silent verifier slashing** | Cannot detect who was "selected but didn't commit" | Accepted limitation (rewards incentivize participation) |
| **Old-epoch batch retry** | Old seed + new snapshot = inconsistent selection | Epoch-bound check: fail batches where `batchEpoch != activeEpoch` |
| **Epoch DoS via startNewEpoch** | Permissionless epoch requests block system | Timeout escape hatch: `cancelStaleEpoch()` after 1-3 hours |
| **Rebuild underflow/double-count** | Forced changes during chunked rebuild | Skip snapshot mutation when `_isSnapshotRebuilding()`, build into Next arrays |
| **Vote counter overflow** | uint8 counters overflow when τ > 255 with retries | Use uint16 for all vote counters |
| **Cancellation stake corruption** | Partial rebuild + cancel = mixed selectionStakes | Block cancel once VRF fulfilled (V3.1 fix) |
| **Finalize gas cost** | Per-verifier SSTORE in chunks | Memory accumulators, batch write at end |
| **Eligibility lookup gas** | O(14) suffix sum per commit | Pre-computed suffix caches, O(1) lookup |
| **Bucket calculation gas** | While loop O(14) worst case | Bit-scan binary search O(4) |
| **batchId committee grinding** | Attacker influences batchId to prefer colluding committee | Store createdEntropy at creation (V3.3 fix) |
| **Eligibility bucket rounding** | Per-verifier check vs denominator inconsistent | Use effective minStake snapped to bucket boundary (V3.2 fix) |
| **batchId collision** | Same params + same block = overwrite | Monotonic nonce + collision check (V3.2 fix) |
| **Roll quantization** | % BPS gives only 10,000 outcomes, rounding to 0 | Math.mulDiv for 256-bit precision (V3.3 fix) |
| **Commit-no-reveal enforcement** | No concrete slashing path | Explicit `slashNoReveal()` function (V3.2 fix) |
| **Finalization liveness** | No incentive to call finalizeEpochChunk() | Pull pattern + count guard (V3.3 fix) |
| **Finalization reentrancy** | safeTransfer in finalizeEpochChunk | nonReentrant + pull pattern (V3.3 fix) |
| **count=0 reward drain** | finalizeEpochChunk(count=0) pays reward | require(count > 0) + end > start check (V3.3 fix) |
| **Swap-pop during rebuild** | _removeFromActiveList corrupts iteration | Block forced changes during rebuild (V3.3 fix) |
| **Slashing during rebuild** | Stale stake in Next arrays | Block slashing during rebuild (V3.3 fix) |
| **blockhash 256-block limit** | blockhash(n) returns 0 after 256 blocks | Store createdEntropy at creation (V3.3 fix) |
| **Epoch spam DoS** | Permissionless startNewEpoch() spam | EPOCH_MIN_INTERVAL rate limit (V3.3 fix) |
| **EPOCH_FINALIZE_TIMEOUT contradiction** | Says can't cancel after fulfilled, but has timeout | Removed - no cancel after VRF (V3.3 fix) |
| **claimUnbonding() breaks invariant** | selectionStake > stakedAmount after claim | Clamp selectionStake if > stakedAmount (V3.3.1 fix) |
| **minBucket==MAX_BUCKETS array OOB** | _getMinBucket returned 14, arrays are length 14 | Open-ended last bucket, never return MAX_BUCKETS (V3.3.2 fix) |
| **Batch value exceeds bucket model** | Large batches cause minStake outside bucket range | MAX_BATCH_VALUE cap (V3.3.2 fix) |
| **Finalization liveness hole** | No one calls finalizeEpochChunk → permanent stall | Auto-finalize for small sets in VRF callback (V3.3.2 fix) |
| **Epoch ID reuse after cancel** | Old VRF fulfillment matches cancelled epoch ID | epochNonce + vrfRequestId check (V3.3.4 fix) |
| **Pause window too broad** | Block operations even before VRF arrives | Narrow to rebuild-only (V3.3.4 fix) |
| **VRF fulfilled but no finalization** | System stuck if no one starts finalization | EPOCH_FINALIZE_TIMEOUT escape hatch (V3.3.4 fix) |
| **Audit batch grinding** | Audit batches lacked createdEntropy | Store createdEntropy + auditBatchNonce (V3.3.4 fix) |
| **Suspension blocked → lost** | Suspension reverted during rebuild, never completed | Deferred suspension + processSuspension() (V3.3.4 fix) |
| **Stake concentration saturation** | Whale with >100% selection probability | MAX_STAKE_SHARE_BPS cap (7%) (V3.3.4 fix) |
| **randomSeed==0 falsely invalid** | Seed 0 is valid but treated as "not ready" | Use epoch.fulfilled flag (V3.3.4 fix) |
| **Finalization reward mining** | Call with count=1 to get full reward | Proportional reward (V3.3.4 fix) |
| **Concentration cap loop backwards** | Checked buckets k..MAX_BUCKETS-1 instead of just k | Check only tightest tier bucket k (V3.3.6 fix) |
| **needsSuspension flag not set** | `_slashVerifier()` emitted event but didn't set flag | Set `needsSuspension[v] = true` before event (V3.3.6 fix) |
| **Rebuild-start griefing** | Anyone can start rebuild with count=1, blocking cancel | Only epochStarter can call first chunk (V3.3.6 fix) |
| **Passive whale concentration** | Concentration only checked on register/addStake | `_checkContinuousConcentration()` at finalization (V3.3.6 fix) |
| **submitReveal reentrancy** | No nonReentrant but calls external JJSKIN | Added nonReentrant modifier (V3.3.6 fix) |
| **StaleEpochBatch error duplicate** | Two different definitions with different params | Unified to single 3-param version (V3.3.6 fix) |

---

## Behavioral Summary

1. **O(1) VRF callback**: Just stores seed, marks fulfilled
2. **Chunked finalization**: `finalizeEpochChunk(epochId, count)` processes verifiers in gas-safe batches (MUST use `pendingEpoch`, MUST have count > 0)
3. **Selection-only snapshots**: Updated at epoch finalization + forced changes
4. **Forced change handling (V3.3.3)**: Slashing uses delta corrections during rebuild, suspension reverts; updates snapshot immediately otherwise
5. **Liveness checks**: `eligibleCount >= QUORUM + 1` before batch creation
6. **Finalization incentives (V3.3)**: Rewards accumulate in `finalizerRewards[]`, withdrawn via `claimFinalizerRewards()`
7. **Epoch rate limiting (V3.3)**: Cannot call `startNewEpoch()` within `EPOCH_MIN_INTERVAL` of previous start
8. **Dynamic τ for retries**: `τ_round = 7 + round * 2` compensates for excluded participants
9. **Unbonding model**: Stake remains slashable until `claimUnbonding()` called
10. **One participation per batch**: Verifiers commit to ONE round per batch
11. **Per-round seeds**: `roundSeed = H(epochSeed, batchId, round, createdEntropy)` ensures different selection each retry
12. **Audit freshness at commit**: Check `committedRoundPlus1/revealedRoundPlus1` on original batch
13. **Epoch transition pause**: V3.3.5: `submitCommit` blocked during rebuild, batch creation blocked when VRF fulfilled
14. **Stake freeze**: Block stake mutations when pending epoch is fulfilled but not finalized
15. **Reveal allowed during transition**: Existing batches in REVEAL_PHASE can still reveal (uses old snapshot)
16. **Epoch-bound batches**: Batches fail on retry if `batchEpoch != activeEpoch` (snapshot was overwritten)
17. **Epoch timeout escape hatch**: `cancelStaleEpoch()` clears stuck pending epoch after VRF or finalize timeout
18. **Snapshot rebuild safety (V3.3.3)**: Slashing uses selectionEpochTag + delta corrections; suspension reverts during rebuild
19. **Double-buffer finalization**: Build into Next arrays, swap to Active on completion
20. **uint16 vote counters**: Prevents overflow on tail cases with high τ
21. **Memory accumulators** (V3.1): Chunk processing uses memory, single batch write to storage
22. **O(1) eligibility lookups** (V3.1): Pre-computed suffix sum caches updated on swap/forced changes
23. **Cancel safety** (V3.1): `cancelStaleEpoch()` reverts once rebuild starts; slashes epoch-starter bond (V3.3.5)
24. **Math.mulDiv for threshold** (V3.3): 512-bit intermediate prevents overflow
25. **createdEntropy stored at creation** (V3.3): Avoids 256-block blockhash staleness
26. **Effective minStake** (V3.2): Bucket-snapped threshold for consistent eligibility
27. **Batch nonce** (V3.2): Monotonic counter prevents batchId collision
28. **slashNoReveal()** (V3.2): Permissionless commit-no-reveal slashing enforcement
29. **Finalization rewards** (V3.3): Pull pattern via finalizerRewards[], claimed separately
30. **SelectionStake clamp** (V3.3.1): `claimUnbonding()` clamps selectionStake to stakedAmount if exceeded
31. **Open-ended last bucket** (V3.3.2): Bucket 13 covers [8.192M, ∞), `_getMinBucket()` never returns 14
32. **Batch value ceiling** (V3.3.2): MAX_BATCH_VALUE prevents minStake exceeding bucket model
33. ~~**Auto-finalize for small sets** (V3.3.2)~~: Removed in V3.3.5 (risky gas estimation, replaced by epoch-starter bond)
34. **Stake-weighted public lottery** (V3.3.2): Selection is publicly verifiable, not true secret sortition
35. **Per-round reveal deadlines** (V3.3.3): `roundRevealDeadline[batchId][round]` stored at commit time for accurate slashNoReveal
36. **Explicit minStake guard** (V3.3.3): `_getMinBucket()` reverts with `MinStakeOutOfRange` instead of silent clamp
37. **Epoch zero defense** (V3.3.3): `fulfillRandomWords()` rejects epoch==0 to guard against mapping default values
38. **Overflow-safe stake*tau** (V3.3.3): Check for overflow with safe failure mode (always selected)
39. **Epoch ID reuse prevention** (V3.3.4): `epochNonce` for unique IDs + `vrfRequestId` check in callback
40. **Rebuild-only pause** (V3.3.4): `_isEpochTransitioning()` now returns `_isSnapshotRebuilding()` (narrowed window)
41. **Fulfilled-no-progress escape** (V3.3.4): `EPOCH_FINALIZE_TIMEOUT` allows cancel if VRF arrived but no one finalized
42. **Audit batch entropy** (V3.3.4): Audit batches now set `createdEntropy` + use `auditBatchNonce` for collision prevention
43. **Deferred suspension** (V3.3.4): `needsSuspension` flag + `processSuspension()` for post-rebuild completion
44. **Stake concentration cap** (V3.3.5): Bucket-aware `_checkConcentration()` replaces global percentage cap
45. **Seed-agnostic readiness** (V3.3.4): Use `epoch.fulfilled` flag, not `randomSeed != 0` (seed 0 is valid)
46. **Proportional finalization reward** (V3.3.4): `reward × processed / CHUNK_SIZE` prevents mining with count=1
47. **Epoch-starter bond** (V3.3.5): 10 USDC bond required to call `startNewEpoch()`, returned on completion
48. **Stale epoch commit rejection** (V3.3.5): `submitCommit` reverts if `batchEpoch != activeEpoch`
49. **VRF-fulfilled batch pause** (V3.3.5): Batch creation blocked when `_isStakeFrozen()` (prevents grinding)
50. **Pure O(1) VRF callback** (V3.3.5): Removed auto-finalize, callback only stores seed + marks fulfilled
51. **τ_max = 11** (V3.3.5): Corrected from 13; MAX_ROUNDS=3 means rounds 0,1,2 (0-indexed)
52. **Removed retrospective audit call** (V3.3.5): Internal `address(this).call` removed from `_completeEpochFinalization`
53. **Single-bucket concentration check** (V3.3.6): Check only tightest tier (bucket k), not k..MAX_BUCKETS-1
54. **Deferred suspension flag fix** (V3.3.6): `_slashVerifier()` now sets `needsSuspension[v] = true`
55. **Rebuild-start griefing protection** (V3.3.6): Only `epochStarter` can call first `finalizeEpochChunk()` chunk
56. **Continuous concentration enforcement** (V3.3.6): `_checkContinuousConcentration()` caps whales at epoch finalization
57. **submitReveal reentrancy guard** (V3.3.6): Added `nonReentrant` modifier to prevent reentrancy via JJSKIN callback

---

## Migration Notes

This is a breaking change requiring:
1. New contract deployment
2. First epoch must be started + fulfilled + finalized before any batches
3. Call `finalizeEpochChunk()` in batches after VRF fulfillment
4. New verifiers have `selectionStake = 0` until epoch finalizes
5. Update `JJSKIN.setOracle()` to point to new contract
6. Existing batches on old contract continue with old logic

---

## Gas Estimates

**V3.1 Optimized:**
- `finalizeEpochChunk(50)`: **~80k gas** (down from ~150k - memory accumulators)
- `fulfillRandomWords()`: ~50k gas (O(1))
- `_isSelected()` eligibility check: **~2k gas** (down from ~5k - O(1) suffix cache)
- `_getBucket()`: **~200 gas** (down from ~500 - bit-scan)
- For 1000 verifiers: 20 chunks × 80k = **1.6M gas** total finalization (down from 3M)

**Per-operation breakdown:**
- Chunk: 30 SSTORE (14 bucket sums + 14 bucket counts + 2 totals) + 50 verifier.selectionStake writes
- Swap + suffix recompute: 14×2 bucket copies + 14×2 suffix cache writes = ~60 SSTORE
- Forced change (slash): bucket update + suffix recompute = ~32 SSTORE
