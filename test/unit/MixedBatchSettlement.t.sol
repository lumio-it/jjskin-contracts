// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title MixedSettlement Tests
/// @notice Tests for mixed releases and refunds via oracle-signed settlements
contract MixedBatchSettlementTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    // ========== Tests ==========

    function test_mixed_releaseAndRefund() public {
        // Setup: 2 purchases, commit both
        JJSKIN.AssetId asset1 = JJSKIN.AssetId.wrap(100);
        JJSKIN.AssetId asset2 = JJSKIN.AssetId.wrap(200);

        _createListingAndPurchase(asset1, seller, buyer, ITEM_PRICE);
        _createListingAndPurchase(asset2, seller, buyer2, ITEM_PRICE);

        vm.prank(seller);
        marketplace.commitTradeOffer(asset1, 1001);
        vm.prank(seller);
        marketplace.commitTradeOffer(asset2, 1002);

        uint256 sellerBalBefore = marketplace.userBalances(seller);
        uint256 buyer2BalBefore = marketplace.userBalances(buyer2);

        // Release asset1, refund asset2
        _oracleClaim(asset1);
        _oracleRefund(asset2, JJSKIN.RefundReason.Timeout);

        // Verify: asset1 released (seller gets paid minus fee)
        (,,JJSKIN.PurchaseStatus status1,) = marketplace.purchases(asset1);
        assertEq(uint8(status1), uint8(JJSKIN.PurchaseStatus.Released));

        uint256 fee = (uint256(ITEM_PRICE) * marketplace.platformFeePercent()) / 10000;
        uint256 expectedSellerAmount = ITEM_PRICE - fee;
        assertEq(marketplace.userBalances(seller) - sellerBalBefore, expectedSellerAmount);

        // Verify: asset2 refunded (buyer2 gets money back)
        (,,JJSKIN.PurchaseStatus status2,) = marketplace.purchases(asset2);
        assertEq(uint8(status2), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(marketplace.userBalances(buyer2) - buyer2BalBefore, ITEM_PRICE);
    }

    function test_mixed_3way() public {
        JJSKIN.AssetId asset1 = JJSKIN.AssetId.wrap(301);
        JJSKIN.AssetId asset2 = JJSKIN.AssetId.wrap(302);
        JJSKIN.AssetId asset3 = JJSKIN.AssetId.wrap(303);

        _createListingAndPurchase(asset1, seller, buyer, ITEM_PRICE);
        _createListingAndPurchase(asset2, seller2, buyer, ITEM_PRICE);
        _createListingAndPurchase(asset3, seller, buyer2, ITEM_PRICE);

        vm.prank(seller);
        marketplace.commitTradeOffer(asset1, 2001);
        vm.prank(seller2);
        marketplace.commitTradeOffer(asset2, 2002);
        vm.prank(seller);
        marketplace.commitTradeOffer(asset3, 2003);

        // release, refund, release
        _oracleClaim(asset1);
        _oracleRefund(asset2, JJSKIN.RefundReason.Timeout);
        _oracleClaim(asset3);

        (,,JJSKIN.PurchaseStatus s1,) = marketplace.purchases(asset1);
        (,,JJSKIN.PurchaseStatus s2,) = marketplace.purchases(asset2);
        (,,JJSKIN.PurchaseStatus s3,) = marketplace.purchases(asset3);

        assertEq(uint8(s1), uint8(JJSKIN.PurchaseStatus.Released));
        assertEq(uint8(s2), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(uint8(s3), uint8(JJSKIN.PurchaseStatus.Released));
    }

    function test_mixed_allRefunds() public {
        JJSKIN.AssetId asset1 = JJSKIN.AssetId.wrap(401);
        JJSKIN.AssetId asset2 = JJSKIN.AssetId.wrap(402);

        _createListingAndPurchase(asset1, seller, buyer, ITEM_PRICE);
        _createListingAndPurchase(asset2, seller2, buyer2, ITEM_PRICE);

        vm.prank(seller);
        marketplace.commitTradeOffer(asset1, 3001);
        vm.prank(seller2);
        marketplace.commitTradeOffer(asset2, 3002);

        // All refunds — no fees collected
        _oracleRefund(asset1, JJSKIN.RefundReason.Timeout);
        _oracleRefund(asset2, JJSKIN.RefundReason.Timeout);

        (,,JJSKIN.PurchaseStatus s1,) = marketplace.purchases(asset1);
        (,,JJSKIN.PurchaseStatus s2,) = marketplace.purchases(asset2);
        assertEq(uint8(s1), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(uint8(s2), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_mixed_duplicateAssetId() public {
        // Same asset settled twice — second call is idempotent (skip)
        JJSKIN.AssetId asset1 = JJSKIN.AssetId.wrap(501);
        _createListingAndPurchase(asset1, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(asset1, 4001);

        // First settlement
        _oracleClaim(asset1);

        uint256 sellerBal = marketplace.userBalances(seller);

        // Second settlement — idempotent skip
        _oracleClaim(asset1);

        (,,JJSKIN.PurchaseStatus s1,) = marketplace.purchases(asset1);
        assertEq(uint8(s1), uint8(JJSKIN.PurchaseStatus.Released));
        assertEq(marketplace.userBalances(seller), sellerBal, "Balance should not change on duplicate");
    }
}
