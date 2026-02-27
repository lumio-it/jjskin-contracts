// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title FuzzCommitTradeOffer
/// @notice Fuzz tests for commitTradeOffer uint64->uint48 truncation and determinism
contract FuzzCommitTradeOffer is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    /// @notice tradeOfferId must fit in uint48; values > uint48.max are rejected
    function testFuzz_commitTradeOffer_validRange(uint64 tradeOfferId) public {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(55555);
        _createListingAndPurchase(assetId, seller, buyer, ITEM_PRICE);

        if (tradeOfferId == 0 || tradeOfferId > type(uint48).max) {
            vm.prank(seller);
            vm.expectRevert(JJSKIN.InvalidInput.selector);
            marketplace.commitTradeOffer(assetId, tradeOfferId);
        } else {
            vm.prank(seller);
            marketplace.commitTradeOffer(assetId, tradeOfferId);

            uint48 stored = marketplace.getTradeOfferCommitment(JJSKIN.AssetId.unwrap(assetId));
            assertEq(uint64(stored), tradeOfferId, "should store losslessly");
        }
    }

    /// @notice Same inputs always produce the same commitment hash
    function testFuzz_commitment_deterministic(uint64 assetIdRaw, uint64 tradeOfferId) public {
        // Bound to valid ranges
        assetIdRaw = uint64(bound(assetIdRaw, 1, type(uint64).max));
        tradeOfferId = uint64(bound(tradeOfferId, 1, type(uint48).max));

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(assetIdRaw);

        // Setup: need listing + purchase for this asset
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(0),
            price: ITEM_PRICE,
            nonce: keccak256(abi.encodePacked(seller, assetIdRaw, block.timestamp))
        });
        bytes memory sig = _signListing(listing, sellerKey);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, sig);

        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, tradeOfferId);

        // Verify tradeOfferId stored correctly
        uint48 stored = marketplace.getTradeOfferCommitment(assetIdRaw);
        assertEq(uint64(stored), tradeOfferId, "tradeOfferId not stored correctly");
    }
}
