// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";
import "./handlers/MarketplaceHandler.sol";

/// @title InvariantMarketplace
/// @notice Invariant tests for JJSKIN marketplace
/// @dev Uses MarketplaceHandler for stateful fuzzing
contract InvariantMarketplace is BaseTest {
    MarketplaceHandler public handler;

    function setUp() public override {
        super.setUp();

        handler = new MarketplaceHandler(
            marketplace,
            usdc,
            seller,
            buyer,
            seller2,
            buyer2,
            sellerKey,
            buyerKey,
            seller2Key,
            buyer2Key,
            oracleKey,
            oracleEOA
        );

        // Target only the handler for invariant calls
        targetContract(address(handler));

        // Fund handler so it can act as orchestrator (receives direct transfers)
        vm.prank(owner);
        usdc.mint(address(handler), 0); // Handler doesn't need USDC, marketplace has it
    }

    // ========== INV-1: Balance Sheet Conservation (Weak) ==========
    /// @notice USDC in marketplace + direct transfers >= totalUserBalances + accumulatedFees
    function invariant_balanceSheetConservation() public view {
        uint256 contractBalance = usdc.balanceOf(address(marketplace));
        uint256 directTransfers = handler.ghost_totalDirectTransfers();
        uint256 totalUserBal = marketplace.totalUserBalances();
        uint256 fees = marketplace.accumulatedFees();

        assertGe(
            contractBalance + directTransfers,
            totalUserBal + fees,
            "INV-1: balance sheet conservation violated"
        );
    }

    // ========== INV-2: totalUserBalances == Sum of Individuals ==========
    /// @notice Aggregate tracker matches sum of individual balances
    function invariant_totalUserBalancesConsistency() public view {
        uint256 sumIndividual = 0;
        uint256 len = handler.getTrackedUsersLength();

        for (uint256 i = 0; i < len; i++) {
            address user = handler.getTrackedUser(i);
            sumIndividual += marketplace.userBalances(user);
        }

        assertGe(
            marketplace.totalUserBalances(),
            sumIndividual,
            "INV-2: totalUserBalances < sum of tracked individuals"
        );
    }

    // ========== INV-3: Fee Conservation Per Settlement ==========
    /// @notice No fee math errors detected during handler operations
    function invariant_feeConservation() public view {
        assertEq(
            handler.ghost_feeConservationViolations(),
            0,
            "INV-3: fee conservation violations detected"
        );
    }

    // ========== INV-4: No Underflow on totalUserBalances ==========
    /// @notice totalUserBalances never exceeds what contract can cover
    function invariant_noNegativeBalances() public view {
        uint256 contractBalance = usdc.balanceOf(address(marketplace));
        uint256 totalUserBal = marketplace.totalUserBalances();

        assertGe(
            contractBalance + handler.ghost_totalEscrowed(),
            totalUserBal,
            "INV-4: totalUserBalances exceeds available funds"
        );
    }

    // ========== INV-5: Buy Order Accounting ==========
    /// @notice Active buy order totalSpent <= maxPricePerItem * initialQuantity
    function invariant_buyOrderAccounting() public view {
        for (uint64 id = 1; id <= 20; id++) {
            JJSKIN.BuyOrderId orderId = JJSKIN.BuyOrderId.wrap(id);
            (address orderBuyer,
             uint8 quantity,
             uint8 initialQuantity,
             JJSKIN.BuyOrderState state,
             uint56 maxPricePerItem,,
             uint128 totalSpent) = marketplace.buyOrders(orderId);

            if (orderBuyer == address(0)) continue;

            if (state == JJSKIN.BuyOrderState.Active || state == JJSKIN.BuyOrderState.Filled) {
                assertLe(
                    totalSpent,
                    uint128(maxPricePerItem) * uint128(initialQuantity),
                    "INV-5: buy order totalSpent exceeds max"
                );
                assertLe(quantity, initialQuantity, "INV-5: quantity > initialQuantity");
            }
        }
    }

    // ========== INV-6: Commitment Integrity ==========
    /// @notice Active purchase with commitment must have tradeOfferId != 0
    function invariant_commitmentIntegrity() public view {
        uint256 committedLen = handler.getCommittedLength();
        uint256 checkCommitted = committedLen > 50 ? 50 : committedLen;

        for (uint256 i = 0; i < checkCommitted; i++) {
            uint64 assetId = handler.getCommittedAsset(i);
            JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

            (, , , uint48 tradeOfferId) = marketplace.purchases(aId);

            assertGt(
                tradeOfferId,
                0,
                "INV-6: committed asset has zero tradeOfferId"
            );
        }
    }

    // ========== INV-7: Handler Effectiveness ==========
    /// @notice After 100+ handler calls, purchase success rate must exceed 10%
    function invariant_handlerEffectiveness() public view {
        uint256 totalCalls = handler.ghost_totalCalls();
        if (totalCalls < 100) return;

        uint256 purchaseSuccess = handler.ghost_purchase_success();
        uint256 purchaseTotal = purchaseSuccess + handler.ghost_purchase_fail();

        if (purchaseTotal == 0) return;

        assertGt(
            purchaseSuccess * 100,
            purchaseTotal * 10,
            "INV-7: purchase success rate <= 10% after 100+ calls"
        );
    }

    // ========== INV-8: Strict USDC Conservation ==========
    /// @notice contractBalance == totalUserBalances + accumulatedFees + escrow + buyOrderLocked
    /// This is the strongest accounting invariant. Every USDC in the contract
    /// must be exactly accounted for across these four categories.
    function invariant_strictUsdcConservation() public view {
        uint256 contractBalance = usdc.balanceOf(address(marketplace));
        uint256 totalUserBal = marketplace.totalUserBalances();
        uint256 fees = marketplace.accumulatedFees();
        uint256 escrowed = handler.ghost_totalEscrowed();
        uint256 buyOrderLocked = handler.ghost_buyOrderLocked();

        assertEq(
            contractBalance,
            totalUserBal + fees + escrowed + buyOrderLocked,
            "INV-8: strict USDC conservation violated"
        );
    }

    // ========== INV-9: Released Asset Listings Persist ==========
    /// @notice After release, listing.exists must remain true
    /// Released items were transferred  - listing data is kept to prevent re-listing
    function invariant_releasedListingsPersist() public view {
        uint256 len = handler.getReleasedLength();
        uint256 check = len > 50 ? 50 : len;

        for (uint256 i = 0; i < check; i++) {
            uint64 assetId = handler.getReleasedAsset(i);
            JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

            (,,bool exists,) = marketplace.listings(aId);
            assertTrue(exists, "INV-9: released asset listing was deleted");
        }
    }

    // ========== INV-10: Refunded Asset Listings Deleted ==========
    /// @notice After refund, listing.exists must be false (allows re-listing)
    /// Only checks assets still in refundedAssets pool (not yet re-listed)
    function invariant_refundedListingsDeleted() public view {
        uint256 len = handler.getRefundedLength();
        uint256 check = len > 50 ? 50 : len;

        for (uint256 i = 0; i < check; i++) {
            uint64 assetId = handler.getRefundedAsset(i);
            JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

            (,,bool exists,) = marketplace.listings(aId);
            assertFalse(exists, "INV-10: refunded asset listing still exists");
        }
    }

    // ========== INV-11: Re-list After Refund Works ==========
    /// @notice If relists were attempted, at least some should succeed
    /// Validates the compound AlreadyPurchased check (buyer != 0 && status == Active)
    function invariant_relistAfterRefundWorks() public view {
        uint256 relistAttempts = handler.ghost_relistSuccess() + handler.ghost_relistFail();
        if (relistAttempts == 0) return;

        assertGt(
            handler.ghost_relistSuccess(),
            0,
            "INV-11: no successful relists despite attempts"
        );
    }

    // ========== INV-12: Purchase Status Consistency ==========
    /// @notice Assets in uncommittedAssets pool must have Active purchase status
    function invariant_uncommittedAssetsActive() public view {
        uint256 len = handler.getUncommittedLength();
        uint256 check = len > 50 ? 50 : len;

        for (uint256 i = 0; i < check; i++) {
            uint64 assetId = handler.getUncommittedAsset(i);
            JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

            (address purchaseBuyer,, JJSKIN.PurchaseStatus status,) = marketplace.purchases(aId);
            assertTrue(purchaseBuyer != address(0), "INV-12: uncommitted asset has no buyer");
            assertEq(
                uint8(status),
                uint8(JJSKIN.PurchaseStatus.Active),
                "INV-12: uncommitted asset not Active"
            );
        }
    }

    // ========== INV-13: Cannot Purchase a Purchased Listing ==========
    /// @notice Attempting to purchase an asset with an active purchase must always be blocked
    function invariant_cannotDoublePurchase() public view {
        assertEq(
            handler.ghost_doublePurchase_leaked(),
            0,
            "INV-13: double purchase succeeded  - AlreadyListed/AlreadyPurchased bypassed"
        );
    }

    // ========== INV-14: Cancelled Listing Cannot Be Purchased ==========
    /// @notice Attempting to purchase with a used/cancelled nonce must always be blocked
    function invariant_cancelledNonceBlocked() public view {
        assertEq(
            handler.ghost_cancelledNonce_leaked(),
            0,
            "INV-14: cancelled nonce purchase succeeded  - nonce system bypassed"
        );
    }

    // ========== INV-15: Committed Assets Active ==========
    /// @notice Assets in committedAssets pool must have Active purchase status
    function invariant_committedAssetsActive() public view {
        uint256 len = handler.getCommittedLength();
        uint256 check = len > 50 ? 50 : len;

        for (uint256 i = 0; i < check; i++) {
            uint64 assetId = handler.getCommittedAsset(i);
            JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

            (address purchaseBuyer,, JJSKIN.PurchaseStatus status,) = marketplace.purchases(aId);
            assertTrue(purchaseBuyer != address(0), "INV-13: committed asset has no buyer");
            assertEq(
                uint8(status),
                uint8(JJSKIN.PurchaseStatus.Active),
                "INV-13: committed asset not Active"
            );
        }
    }
}
