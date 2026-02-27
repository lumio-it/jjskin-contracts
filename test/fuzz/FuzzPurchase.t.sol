// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title FuzzPurchase
/// @notice Fuzz tests for purchase price handling and partial balance logic
contract FuzzPurchase is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    /// @notice Any valid price creates a correct purchase
    function testFuzz_purchase_price(uint56 price) public {
        price = uint56(bound(price, 1, 1e12)); // 1 unit to 1M USDC

        // Make sure buyer has enough
        vm.prank(owner);
        usdc.mint(buyer, uint256(price));

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(price)); // Unique per price

        JJSKIN.ListingData memory listing = _createListingData(assetId, seller, price);
        bytes memory sig = _signListing(listing, sellerKey);

        uint256 buyerUsdcBefore = usdc.balanceOf(buyer);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, sig);

        // Verify purchase exists and is active
        (address purchaseBuyer,, JJSKIN.PurchaseStatus status,) = marketplace.purchases(assetId);
        assertEq(purchaseBuyer, buyer);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));

        // Buyer should have paid exactly `price`
        uint256 buyerUsdcAfter = usdc.balanceOf(buyer);
        assertEq(buyerUsdcBefore - buyerUsdcAfter, price, "incorrect USDC deduction");
    }

    /// @notice Balance-first-then-wallet logic is correct for partial balances
    function testFuzz_purchase_partialBalance(uint56 price, uint256 balance) public {
        price = uint56(bound(price, 1_000_000, 100_000_000)); // $1-$100
        balance = bound(balance, 0, uint256(price));

        // Give buyer some internal balance by doing a refund cycle
        if (balance > 0) {
            // Create and refund a purchase to give buyer internal balance
            JJSKIN.AssetId tempAsset = JJSKIN.AssetId.wrap(99999);
            uint56 tempPrice = uint56(balance);
            if (tempPrice == 0) tempPrice = 1;

            JJSKIN.ListingData memory tempListing = _createListingData(tempAsset, seller, tempPrice);
            bytes memory tempSig = _signListing(tempListing, sellerKey);

            vm.prank(buyer);
            marketplace.purchaseWithSignature(tempListing, seller, tempSig);

            // Timeout refund to get balance
            vm.warp(block.timestamp + 24 hours + 1);
            marketplace.claimTimeoutRefund(tempAsset);

            // Now buyer has userBalance == tempPrice
        }

        uint256 buyerBalance = marketplace.userBalances(buyer);
        uint256 buyerUsdc = usdc.balanceOf(buyer);

        // Ensure buyer can afford the purchase
        vm.assume(buyerBalance + buyerUsdc >= price);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(price) + 10000);
        JJSKIN.ListingData memory listing = _createListingData(assetId, seller, price);
        bytes memory sig = _signListing(listing, sellerKey);

        uint256 balBefore = marketplace.userBalances(buyer);
        uint256 usdcBefore = usdc.balanceOf(buyer);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, sig);

        uint256 balAfter = marketplace.userBalances(buyer);
        uint256 usdcAfter = usdc.balanceOf(buyer);

        // Total spent should equal price
        uint256 balUsed = balBefore - balAfter;
        uint256 usdcUsed = usdcBefore - usdcAfter;
        assertEq(balUsed + usdcUsed, price, "total payment != price");

        // Balance should be used first
        if (balBefore >= price) {
            assertEq(usdcUsed, 0, "should not pull USDC when balance covers");
        }
    }
}
