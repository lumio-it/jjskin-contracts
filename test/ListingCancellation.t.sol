// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, console2} from "forge-std/Test.sol";
import "./base/BaseTest.sol";

/**
 * @title ListingCancellationTest
 * @notice Tests for on-chain listing cancellation (LUM-35)
 * @dev Prevents signature replay attacks when seller cancels or updates price
 */
contract ListingCancellationTest is BaseTest {

    // ========== Events ==========
    event ListingCancelled(address indexed seller, bytes32 indexed nonce);

    // ========== Setup ==========

    function setUp() public override {
        super.setUp();
    }

    // ========== Helper Functions ==========

    function _createTestListing(uint64 assetIdNum) internal view returns (
        JJSKIN.ListingData memory listing,
        bytes memory signature
    ) {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(assetIdNum);
        listing = _createListingData(assetId, seller, ITEM_PRICE);
        signature = _signListing(listing, sellerKey);
    }

    // ========== Cancel Single Listing Tests ==========

    function test_CancelListing_Success() public {
        // Create listing
        (JJSKIN.ListingData memory listing,) = _createTestListing(1001);

        // Cancel listing
        vm.prank(seller);
        vm.expectEmit(true, true, false, false);
        emit ListingCancelled(seller, listing.nonce);
        marketplace.cancelListing(listing.nonce);

        // Verify cancelled
        assertTrue(marketplace.isListingCancelled(seller, listing.nonce));
    }

    function test_CancelListing_PreventsPurchase() public {
        // Create and sign listing
        (JJSKIN.ListingData memory listing, bytes memory signature) = _createTestListing(1002);

        // Cancel listing BEFORE purchase
        vm.prank(seller);
        marketplace.cancelListing(listing.nonce);

        // Try to purchase - should revert
        vm.prank(buyer);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    function test_CancelListing_OnlyAffectsSeller() public {
        // Create listing for seller
        (JJSKIN.ListingData memory listing,) = _createTestListing(1003);

        // Another seller cancels THEIR nonce (not seller's)
        vm.prank(seller2);
        marketplace.cancelListing(listing.nonce);

        // Original seller's nonce should NOT be cancelled
        assertFalse(marketplace.isListingCancelled(seller, listing.nonce));

        // seller2's should be cancelled
        assertTrue(marketplace.isListingCancelled(seller2, listing.nonce));
    }

    function test_CancelListing_Idempotent() public {
        (JJSKIN.ListingData memory listing,) = _createTestListing(1004);

        // Cancel same listing twice - should not revert
        vm.startPrank(seller);
        marketplace.cancelListing(listing.nonce);
        marketplace.cancelListing(listing.nonce); // Second cancel is no-op
        vm.stopPrank();

        assertTrue(marketplace.isListingCancelled(seller, listing.nonce));
    }

    // ========== Batch Cancel Tests ==========

    function test_CancelListings_Batch() public {
        // Create multiple listings
        bytes32[] memory nonces = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            (JJSKIN.ListingData memory listing,) = _createTestListing(uint64(2001 + i));
            nonces[i] = listing.nonce;
        }

        // Batch cancel
        vm.prank(seller);
        marketplace.cancelListings(nonces);

        // Verify all cancelled
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(marketplace.isListingCancelled(seller, nonces[i]));
        }
    }

    function test_CancelListings_BatchPreventsAllPurchases() public {
        // Create 3 listings with signatures
        JJSKIN.ListingData[] memory listings = new JJSKIN.ListingData[](3);
        bytes[] memory signatures = new bytes[](3);
        bytes32[] memory nonces = new bytes32[](3);

        for (uint256 i = 0; i < 3; i++) {
            JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(3001 + i));
            listings[i] = _createListingData(assetId, seller, ITEM_PRICE);
            signatures[i] = _signListing(listings[i], sellerKey);
            nonces[i] = listings[i].nonce;
        }

        // Batch cancel all
        vm.prank(seller);
        marketplace.cancelListings(nonces);

        // Try to purchase each - all should revert
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(buyer);
            vm.expectRevert(JJSKIN.NonceInvalid.selector);
            marketplace.purchaseWithSignature(listings[i], seller, signatures[i]);
        }
    }

    function test_CancelListings_EmptyArray() public {
        bytes32[] memory nonces = new bytes32[](0);

        // Should not revert with empty array
        vm.prank(seller);
        marketplace.cancelListings(nonces);
    }

    // ========== Update Price Flow Tests ==========

    function test_UpdatePrice_CancelOldAndCreateNew() public {
        // Create original listing at $10
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(4001);
        JJSKIN.ListingData memory oldListing = _createListingData(assetId, seller, ITEM_PRICE);
        bytes memory oldSignature = _signListing(oldListing, sellerKey);

        // Cancel old listing
        vm.prank(seller);
        marketplace.cancelListing(oldListing.nonce);

        // Create new listing at $15 with NEW nonce
        uint56 newPrice = 15_000_000; // $15
        JJSKIN.ListingData memory newListing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(0),
            price: newPrice,
            nonce: keccak256(abi.encodePacked(seller, assetId, block.timestamp + 1)) // Different nonce
        });
        bytes memory newSignature = _signListing(newListing, sellerKey);

        // Old signature should fail
        vm.prank(buyer);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(oldListing, seller, oldSignature);

        // New signature should work
        vm.prank(buyer);
        marketplace.purchaseWithSignature(newListing, seller, newSignature);

        // Verify purchase at new price
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));
    }

    // ========== Buy Order Match Cancellation Tests ==========

    function test_CancelListing_PreventsBuyOrderMatch() public {
        // Create buy order
        ItemSpec itemSpec = ItemSpec.wrap(123);
        uint56 maxPrice = ITEM_PRICE;

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(itemSpec, maxPrice, 1);

        // Create matching listing
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(5001);
        ItemDetail itemDetail = ItemDetail.wrap(123);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, itemDetail);
        bytes memory signature = _signListing(listing, sellerKey);

        // Cancel listing
        vm.prank(seller);
        marketplace.cancelListing(listing.nonce);

        // Try to match - should revert
        bytes memory oracleSig = _signOracleAttestation(assetId, itemDetail);
        vm.prank(address(this));
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, signature, oracleSig);
    }

    // ========== View Function Tests ==========

    function test_IsListingCancelled_ReturnsFalseForUncancelled() public view {
        bytes32 randomNonce = keccak256("random");
        assertFalse(marketplace.isListingCancelled(seller, randomNonce));
    }

    function test_IsListingCancelled_ReturnsTrueForCancelled() public {
        bytes32 nonce = keccak256("test_nonce");

        vm.prank(seller);
        marketplace.cancelListing(nonce);

        assertTrue(marketplace.isListingCancelled(seller, nonce));
    }

    // ========== Security Tests ==========

    function test_CancelListing_CannotCancelOtherSellerNonce() public {
        (JJSKIN.ListingData memory listing, bytes memory signature) = _createTestListing(6001);

        // Attacker tries to cancel seller's listing
        vm.prank(attacker);
        marketplace.cancelListing(listing.nonce);

        // Seller's listing is NOT cancelled (attacker cancelled their own mapping entry)
        assertFalse(marketplace.isListingCancelled(seller, listing.nonce));

        // Purchase should still work
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    function test_SignatureReplayPrevented_AfterCancel() public {
        // Scenario: Attacker captures old signature
        (JJSKIN.ListingData memory listing, bytes memory signature) = _createTestListing(7001);

        // Seller cancels listing (e.g., wants to update price)
        vm.prank(seller);
        marketplace.cancelListing(listing.nonce);

        // Fund and register attacker (must prank owner for mint)
        vm.prank(owner);
        usdc.mint(attacker, ITEM_PRICE);
        _registerWallet(attacker, 76561198000000099);
        vm.prank(attacker);
        usdc.approve(address(marketplace), type(uint256).max);

        // Attacker tries to use captured signature - should fail
        vm.prank(attacker);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    // ========== Gas Tests ==========

    function test_CancelListing_GasCost() public {
        (JJSKIN.ListingData memory listing,) = _createTestListing(8001);

        vm.prank(seller);
        uint256 gasBefore = gasleft();
        marketplace.cancelListing(listing.nonce);
        uint256 gasUsed = gasBefore - gasleft();

        // Should be ~25k gas on Arbitrum
        assertLt(gasUsed, 50000, "Cancel single listing should use < 50k gas");
        console2.log("Single cancel gas:", gasUsed);
    }

    function test_CancelListings_BatchGasCost() public {
        uint256 batchSize = 10;
        bytes32[] memory nonces = new bytes32[](batchSize);

        for (uint256 i = 0; i < batchSize; i++) {
            (JJSKIN.ListingData memory listing,) = _createTestListing(uint64(9001 + i));
            nonces[i] = listing.nonce;
        }

        vm.prank(seller);
        uint256 gasBefore = gasleft();
        marketplace.cancelListings(nonces);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("Batch cancel (10) gas:", gasUsed);
        // Should be efficient - roughly 10x single + overhead
        assertLt(gasUsed, 300000, "Batch cancel 10 should use < 300k gas");
    }
}
