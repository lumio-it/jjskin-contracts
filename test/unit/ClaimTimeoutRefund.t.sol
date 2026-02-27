// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title ClaimTimeoutRefund Tests
/// @notice Boundary and edge case tests for claimTimeoutRefund()
contract ClaimTimeoutRefundTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    function test_claimTimeoutRefund_exactly24h_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        // Warp to exactly 24 hours — boundary: <= means exactly 24h reverts
        (, uint40 purchaseTime,,) = marketplace.purchases(ASSET_ID);
        vm.warp(uint256(purchaseTime) + 24 hours);

        vm.expectRevert(JJSKIN.TooEarly.selector);
        marketplace.claimTimeoutRefund(ASSET_ID);
    }

    function test_claimTimeoutRefund_24hPlus1_succeeds() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        (, uint40 purchaseTime,,) = marketplace.purchases(ASSET_ID);
        vm.warp(uint256(purchaseTime) + 24 hours + 1);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);

        marketplace.claimTimeoutRefund(ASSET_ID);

        assertEq(marketplace.userBalances(buyer) - buyerBalBefore, ITEM_PRICE);

        (,,JJSKIN.PurchaseStatus status,) = marketplace.purchases(ASSET_ID);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_claimTimeoutRefund_sellerCommitted_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        // Seller commits trade offer
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        // Warp past 24h
        (, uint40 purchaseTime,,) = marketplace.purchases(ASSET_ID);
        vm.warp(uint256(purchaseTime) + 24 hours + 1);

        vm.expectRevert(JJSKIN.SellerAlreadyCommitted.selector);
        marketplace.claimTimeoutRefund(ASSET_ID);
    }

    function test_claimTimeoutRefund_buyOrderMatch_creditsUserBalance() public {
        // Timeout refund from buy-order-matched purchase credits buyer's userBalance
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        // Match one item against the buy order (qty goes to 1)
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(9001);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        (,uint8 qty,,,,,) = marketplace.buyOrders(orderId);
        assertEq(qty, 1, "quantity should be 1 after match");

        uint256 balBefore = marketplace.userBalances(buyer);

        // Warp and claim timeout
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(assetId);

        // Buy order quantity unchanged, refund to userBalance
        (,uint8 qtyAfter,,,,,) = marketplace.buyOrders(orderId);
        assertEq(qtyAfter, 1, "quantity unchanged");
        assertGt(marketplace.userBalances(buyer), balBefore, "buyer credited");
    }

    function test_claimTimeoutRefund_cancelledBuyOrder() public {
        // Match buy order, cancel the buy order, then timeout refund
        // Refund should go to userBalance since buy order is cancelled
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        // Match one item
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(9002);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Cancel the buy order
        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        // Warp and claim timeout — refund goes to userBalance (not buy order)
        vm.warp(block.timestamp + 24 hours + 1);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);
        marketplace.claimTimeoutRefund(assetId);

        assertEq(marketplace.userBalances(buyer) - buyerBalBefore, ITEM_PRICE, "refund to userBalance");
    }

    function test_claimTimeoutRefund_anyoneCanCall() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.warp(block.timestamp + 24 hours + 1);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);

        // Random address triggers the refund
        vm.prank(attacker);
        marketplace.claimTimeoutRefund(ASSET_ID);

        // Funds go to buyer, not to caller
        assertEq(marketplace.userBalances(buyer) - buyerBalBefore, ITEM_PRICE);
        assertEq(marketplace.userBalances(attacker), 0);
    }

    function test_claimTimeoutRefund_alreadyRefunded_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);

        // Second call should revert
        vm.expectRevert(JJSKIN.InvalidTradeState.selector);
        marketplace.claimTimeoutRefund(ASSET_ID);
    }
}
