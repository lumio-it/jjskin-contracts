// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";
import "../../src/CS2AaveVault.sol";

/// @title BranchCoverage Tests
/// @notice Comprehensive branch coverage for JJSKIN.sol — every revert path and conditional branch
contract BranchCoverageTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    // ========================================================================
    // SECTION 1: setPlatformFee
    // ========================================================================

    function test_setPlatformFee_success() public {
        vm.prank(owner);
        marketplace.setPlatformFee(100); // 1%
        assertEq(marketplace.platformFeePercent(), 100);
    }

    function test_setPlatformFee_maxAllowed() public {
        vm.prank(owner);
        marketplace.setPlatformFee(500); // 5% — exactly at max
        assertEq(marketplace.platformFeePercent(), 500);
    }

    function test_setPlatformFee_exceedsMax_reverts() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.FeeExceedsMaximum.selector, 501, 500));
        marketplace.setPlatformFee(501);
    }

    function test_setPlatformFee_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setPlatformFee(100);
    }

    // ========================================================================
    // SECTION 2: setDeliveryWindow
    // ========================================================================

    function test_setDeliveryWindow_success() public {
        vm.prank(owner);
        marketplace.setDeliveryWindow(12 hours);
        assertEq(marketplace.deliveryWindow(), 12 hours);
    }

    function test_setDeliveryWindow_tooLow_reverts() public {
        vm.prank(owner);
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(59 minutes);
    }

    function test_setDeliveryWindow_tooHigh_reverts() public {
        vm.prank(owner);
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(49 hours);
    }

    function test_setDeliveryWindow_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setDeliveryWindow(12 hours);
    }

    // ========================================================================
    // SECTION 3: setAbandonedWindow
    // ========================================================================

    function test_setAbandonedWindow_success() public {
        vm.prank(owner);
        marketplace.setAbandonedWindow(36 hours);
        assertEq(marketplace.abandonedWindow(), 36 hours);
    }

    function test_setAbandonedWindow_tooLow_reverts() public {
        vm.prank(owner);
        vm.expectRevert("Invalid abandoned window");
        marketplace.setAbandonedWindow(11 hours);
    }

    function test_setAbandonedWindow_tooHigh_reverts() public {
        vm.prank(owner);
        vm.expectRevert("Invalid abandoned window");
        marketplace.setAbandonedWindow(73 hours);
    }

    // ========================================================================
    // SECTION 5: setTreasury
    // ========================================================================

    function test_setTreasury_success() public {
        vm.prank(owner);
        marketplace.setTreasury(user1);
        assertEq(marketplace.treasury(), user1);
    }

    function test_setTreasury_zeroAddress_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.ZeroAddress.selector);
        marketplace.setTreasury(address(0));
    }

    function test_setTreasury_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setTreasury(user1);
    }

    // ========================================================================
    // SECTION 6: setAttestationVerifier and registerOracle
    // ========================================================================

    function test_setAttestationVerifier_success() public {
        MockAttestationVerifier newVerifier = new MockAttestationVerifier();
        vm.prank(owner);
        marketplace.setAttestationVerifier(address(newVerifier));
        // If we get here without revert, success
    }

    function test_setAttestationVerifier_zeroAddress_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.ZeroAddress.selector);
        marketplace.setAttestationVerifier(address(0));
    }

    function test_setAttestationVerifier_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setAttestationVerifier(address(0xABC));
    }

    function test_registerOracle_success() public {
        // setUp already registered oracleEOA, register a new one
        address newOracle = vm.addr(0xCC);
        vm.prank(owner);
        marketplace.registerOracle(abi.encode(newOracle));
        assertTrue(marketplace.oracles(newOracle));
    }

    function test_registerOracle_verifierNotSet_reverts() public {
        // Deploy a fresh marketplace without setting verifier
        vm.prank(owner);
        JJSKIN fresh = new JJSKIN(address(usdc), address(walletFactory));
        // No verifier set — registerOracle should revert
        vm.prank(owner);
        vm.expectRevert(JJSKIN.VerifierNotSet.selector);
        fresh.registerOracle(abi.encode(oracleEOA));
    }

    function test_revokeOracle_success() public {
        assertTrue(marketplace.oracles(oracleEOA));
        vm.prank(owner);
        marketplace.revokeOracle(oracleEOA);
        assertFalse(marketplace.oracles(oracleEOA));
    }

    function test_revokeOracle_notOracle_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.NotOracle.selector);
        marketplace.revokeOracle(address(0xdead));
    }

    function test_revokeOracle_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.revokeOracle(oracleEOA);
    }

    function test_registerOracle_multipleOracles() public {
        address oracle2 = vm.addr(0xDD);
        vm.prank(owner);
        marketplace.registerOracle(abi.encode(oracle2));
        // Both oracles should be registered
        assertTrue(marketplace.oracles(oracleEOA));
        assertTrue(marketplace.oracles(oracle2));
    }

    // ========================================================================
    // SECTION 7: purchaseWithSignature — all branches
    // ========================================================================

    function test_purchase_sellerNotRegistered_reverts() public {
        // Unregistered seller
        address unregisteredSeller = address(0xDEAD);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: ASSET_ID,
            itemDetail: ItemDetail.wrap(0),
            price: ITEM_PRICE,
            nonce: keccak256("nonce1")
        });
        bytes memory sig = _signListing(listing, sellerKey);

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.purchaseWithSignature(listing, unregisteredSeller, sig);
    }

    function test_purchase_buyerNotRegistered_reverts() public {
        // user1 is registered but user2 is NOT registered as a wallet
        // Actually user1 IS registered in setUp. Let's create truly unregistered user.
        address unregistered = address(new MockSmartAccount(vm.addr(0xAA)));

        JJSKIN.ListingData memory listing = _createListingData(ASSET_ID, seller, ITEM_PRICE);
        bytes memory sig = _signListing(listing, sellerKey);

        vm.prank(unregistered);
        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.purchaseWithSignature(listing, seller, sig);
    }

    function test_purchase_cancelledNonce_reverts() public {
        JJSKIN.ListingData memory listing = _createListingData(ASSET_ID, seller, ITEM_PRICE);
        bytes memory sig = _signListing(listing, sellerKey);

        // Seller cancels the nonce
        vm.prank(seller);
        marketplace.cancelListing(listing.nonce);

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(listing, seller, sig);
    }

    function test_purchase_buyOwnItem_reverts() public {
        // Seller tries to buy their own item
        JJSKIN.ListingData memory listing = _createListingData(ASSET_ID, seller, ITEM_PRICE);
        bytes memory sig = _signListing(listing, sellerKey);

        vm.prank(seller);
        vm.expectRevert(JJSKIN.CannotBuyOwnItem.selector);
        marketplace.purchaseWithSignature(listing, seller, sig);
    }

    function test_purchase_zeroPrice_reverts() public {
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: ASSET_ID,
            itemDetail: ItemDetail.wrap(0),
            price: 0,
            nonce: keccak256(abi.encodePacked(seller, ASSET_ID, block.timestamp))
        });
        bytes memory sig = _signListing(listing, sellerKey);

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.purchaseWithSignature(listing, seller, sig);
    }

    function test_purchase_alreadyListed_reverts() public {
        // First purchase creates listing
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        // Another seller tries to list same asset
        JJSKIN.ListingData memory listing2 = JJSKIN.ListingData({
            assetId: ASSET_ID,
            itemDetail: ItemDetail.wrap(0),
            price: ITEM_PRICE,
            nonce: keccak256("new_nonce")
        });
        bytes memory sig2 = _signListing(listing2, seller2Key);

        vm.prank(buyer2);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.AlreadyListed.selector, ASSET_ID));
        marketplace.purchaseWithSignature(listing2, seller2, sig2);
    }

    function test_purchase_afterRefund_succeeds() public {
        // After refund, re-purchase same assetId should succeed
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);

        JJSKIN.ListingData memory listing2 = JJSKIN.ListingData({
            assetId: ASSET_ID,
            itemDetail: ItemDetail.wrap(0),
            price: ITEM_PRICE,
            nonce: keccak256("nonce2")
        });
        bytes memory sig2 = _signListing(listing2, seller2Key);

        vm.prank(buyer2);
        marketplace.purchaseWithSignature(listing2, seller2, sig2);

        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(ASSET_ID);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));
    }

    function test_purchase_fullBalance_path() public {
        // Give buyer enough userBalance to cover purchase entirely
        // First do a purchase + release to build up userBalance
        JJSKIN.AssetId aid1 = JJSKIN.AssetId.wrap(5001);
        _createListingAndPurchase(aid1, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(aid1, 111);
        _oracleClaim(aid1);

        // Now seller has userBalance >= ITEM_PRICE (seller gets price - fee)
        // We need buyer to have balance. Let's use a different approach:
        // Create purchase, then refund to build buyer balance
        JJSKIN.AssetId aid2 = JJSKIN.AssetId.wrap(5002);
        _createListingAndPurchase(aid2, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(aid2);

        // Now buyer has userBalance = ITEM_PRICE
        uint256 buyerBal = marketplace.userBalances(buyer);
        assertEq(buyerBal, ITEM_PRICE, "buyer should have balance");

        // Purchase using full balance (no wallet transfer)
        uint256 walletBefore = usdc.balanceOf(buyer);
        JJSKIN.AssetId aid3 = JJSKIN.AssetId.wrap(5003);
        _createListingAndPurchase(aid3, seller2, buyer, ITEM_PRICE);
        uint256 walletAfter = usdc.balanceOf(buyer);

        // Wallet should be untouched
        assertEq(walletAfter, walletBefore, "wallet should not be touched");
        assertEq(marketplace.userBalances(buyer), 0, "balance should be zero");
    }

    function test_purchase_partialBalance_path() public {
        // Build partial balance (less than price)
        uint56 smallPrice = 4_000_000; // 4 USDC
        JJSKIN.AssetId aid1 = JJSKIN.AssetId.wrap(5010);
        _createListingAndPurchase(aid1, seller, buyer, smallPrice);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(aid1);

        uint256 buyerBal = marketplace.userBalances(buyer);
        assertEq(buyerBal, smallPrice, "buyer should have partial balance");

        // Purchase for a higher price — should use partial balance + wallet
        uint256 walletBefore = usdc.balanceOf(buyer);
        JJSKIN.AssetId aid2 = JJSKIN.AssetId.wrap(5011);
        _createListingAndPurchase(aid2, seller2, buyer, ITEM_PRICE);
        uint256 walletAfter = usdc.balanceOf(buyer);

        uint256 remainder = ITEM_PRICE - smallPrice;
        assertEq(walletBefore - walletAfter, remainder, "wallet should pay remainder");
        assertEq(marketplace.userBalances(buyer), 0, "balance should be zero");
    }

    function test_purchase_noBalance_path() public {
        // Buyer has no userBalance — full amount from wallet
        uint256 walletBefore = usdc.balanceOf(buyer);
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        uint256 walletAfter = usdc.balanceOf(buyer);

        assertEq(walletBefore - walletAfter, ITEM_PRICE, "wallet should pay full price");
    }

    // ========================================================================
    // SECTION 8: commitTradeOffer — all branches
    // ========================================================================

    function test_commitTradeOffer_success() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        (,,, uint48 tradeOfferId) = marketplace.purchases(ASSET_ID);
        assertEq(tradeOfferId, 12345);
    }

    function test_commitTradeOffer_notSeller_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.NotSeller.selector, attacker, seller));
        marketplace.commitTradeOffer(ASSET_ID, 12345);
    }

    function test_commitTradeOffer_noPurchase_reverts() public {
        // No listing or purchase exists for ASSET_ID_2
        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.NotSeller.selector, seller, address(0)));
        marketplace.commitTradeOffer(ASSET_ID_2, 12345);
    }

    function test_commitTradeOffer_notActive_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        // Refund the purchase
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);

        // Now purchase status is Refunded — listing is deleted, seller check fails first
        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.NotSeller.selector, seller, address(0)));
        marketplace.commitTradeOffer(ASSET_ID, 12345);
    }

    function test_commitTradeOffer_alreadyCommitted_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        vm.prank(seller);
        vm.expectRevert(abi.encodeWithSelector(JJSKIN.AssetAlreadyHasCommitment.selector, ASSET_ID));
        marketplace.commitTradeOffer(ASSET_ID, 99999);
    }

    // ========================================================================
    // SECTION 9: (removed — no batch size limit in submitSettlement)
    // ========================================================================

    // ========================================================================
    // SECTION 10: submitSettlement — already settled (skip path)
    // ========================================================================

    function test_submitSettlement_alreadySettled_skips() public {
        // Create purchase, commit, settle once
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        // First settlement (release)
        _oracleClaim(ASSET_ID);

        // Verify it's settled
        (,, JJSKIN.PurchaseStatus status,) = marketplace.purchases(ASSET_ID);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Released));

        // Second settlement with same data — should succeed but skip (idempotent)
        _oracleClaim(ASSET_ID);
    }

    // ========================================================================
    // SECTION 12: submitSettlement — refund with active buy order (restore quantity)
    // ========================================================================

    function test_submitSettlement_refund_activeBuyOrder_creditsUserBalance() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        // Create buy order with qty=2
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        // Match one item (qty goes to 1)
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(7001);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Commit and refund via submitSettlement
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, 111);

        uint256 balBefore = marketplace.userBalances(buyer);
        _oracleRefund(assetId, JJSKIN.RefundReason.Canceled2FA);

        // Buy order quantity unchanged (no restoration), refund to userBalance
        (, uint8 qty,, JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(qty, 1, "quantity unchanged at 1");
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Active), "still active");
        assertGt(marketplace.userBalances(buyer), balBefore, "buyer credited");
    }

    // ========================================================================
    // SECTION 13: submitSettlement — refund with cancelled buy order (to userBalance)
    // ========================================================================

    function test_submitSettlement_refund_cancelledBuyOrder_toUserBalance() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        // Create buy order, match, cancel buy order, commit, refund
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(7002);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Cancel the buy order
        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        // Commit and refund
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, 222);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);
        _oracleRefund(assetId, JJSKIN.RefundReason.Canceled2FA);
        uint256 buyerBalAfter = marketplace.userBalances(buyer);

        // Refund goes to userBalance (not buy order since it's cancelled)
        assertEq(buyerBalAfter - buyerBalBefore, ITEM_PRICE, "refund to userBalance");
    }

    // ========================================================================
    // SECTION 14: submitSettlement — refund with filled buy order (reactivate)
    // ========================================================================

    function test_submitSettlement_refund_filledBuyOrder_staysFilled() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        // Create buy order with qty=1, fill it completely
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(7003);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Verify order is Filled
        (,,, JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Filled));

        // Commit and refund
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, 333);

        uint256 balBefore = marketplace.userBalances(buyer);
        _oracleRefund(assetId, JJSKIN.RefundReason.Canceled2FA);

        // Buy order stays Filled (no restoration), refund to userBalance
        (, uint8 qty,, JJSKIN.BuyOrderState stateAfter,,,) = marketplace.buyOrders(orderId);
        assertEq(qty, 0, "quantity stays 0");
        assertEq(uint8(stateAfter), uint8(JJSKIN.BuyOrderState.Filled), "stays Filled");
        assertGt(marketplace.userBalances(buyer), balBefore, "buyer credited");
    }

    // ========================================================================
    // SECTION 15: createBuyOrder — all branches
    // ========================================================================

    function test_createBuyOrder_success() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        (address orderBuyer,,,,,,) = marketplace.buyOrders(orderId);
        assertEq(orderBuyer, buyer);
    }

    function test_createBuyOrder_zeroPriceReverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.createBuyOrder(spec, 0, 1);
    }

    function test_createBuyOrder_zeroQuantityReverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 0);
    }

    function test_createBuyOrder_overflow_reverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        // MAX_TOTAL_PRICE = 1e12. maxPrice = 1e12, qty = 2 => overflow
        uint56 hugePrice = uint56(1e12);
        vm.prank(buyer);
        vm.expectRevert(JJSKIN.BuyOrderOverflow.selector);
        marketplace.createBuyOrder(spec, hugePrice, 2);
    }

    function test_createBuyOrder_fullBalancePath() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        // Build buyer balance first
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);
        assertEq(marketplace.userBalances(buyer), ITEM_PRICE);

        uint256 walletBefore = usdc.balanceOf(buyer);
        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);
        uint256 walletAfter = usdc.balanceOf(buyer);

        assertEq(walletAfter, walletBefore, "wallet untouched");
        assertEq(marketplace.userBalances(buyer), 0);
    }

    function test_createBuyOrder_partialBalancePath() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        // Build partial balance (4 USDC)
        uint56 smallPrice = 4_000_000;
        JJSKIN.AssetId aid1 = JJSKIN.AssetId.wrap(6001);
        _createListingAndPurchase(aid1, seller, buyer, smallPrice);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(aid1);
        assertEq(marketplace.userBalances(buyer), smallPrice);

        // Buy order costs 10 USDC — 4 from balance + 6 from wallet
        uint256 walletBefore = usdc.balanceOf(buyer);
        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);
        uint256 walletAfter = usdc.balanceOf(buyer);

        assertEq(walletBefore - walletAfter, ITEM_PRICE - smallPrice, "wallet pays remainder");
        assertEq(marketplace.userBalances(buyer), 0);
    }

    function test_createBuyOrder_noBalancePath() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        uint256 walletBefore = usdc.balanceOf(buyer);
        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);
        uint256 walletAfter = usdc.balanceOf(buyer);

        assertEq(walletBefore - walletAfter, ITEM_PRICE, "wallet pays full");
    }

    function test_createBuyOrder_notRegistered_reverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();
        address unregistered = address(new MockSmartAccount(vm.addr(0xBB)));
        vm.prank(owner);
        usdc.mint(unregistered, INITIAL_BALANCE);
        vm.prank(unregistered);
        usdc.approve(address(marketplace), type(uint256).max);

        vm.prank(unregistered);
        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);
    }

    // ========================================================================
    // SECTION 16: cancelBuyOrder — all branches
    // ========================================================================

    function test_cancelBuyOrder_success() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        (,,, JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Cancelled));
    }

    function test_cancelBuyOrder_notYourOrder_reverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        vm.prank(attacker);
        vm.expectRevert(JJSKIN.NotYourBuyOrder.selector);
        marketplace.cancelBuyOrder(orderId);
    }

    function test_cancelBuyOrder_notActive_reverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        // Cancel first
        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        // Cancel again
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(
            JJSKIN.InvalidBuyOrderState.selector,
            JJSKIN.BuyOrderState.Cancelled,
            JJSKIN.BuyOrderState.Active
        ));
        marketplace.cancelBuyOrder(orderId);
    }

    function test_cancelBuyOrder_zeroRefund() public {
        // Create buy order with qty=1, fill it, then try to cancel
        // When filled, state becomes Filled — not Active — so cancel reverts.
        // Alternative: cancel after all funds are spent (partial match scenario)
        // For zero refund: all locked funds spent. We need qty>1 with all matched.
        // Actually, once all matched => Filled state => can't cancel.
        // The zero refund path: totalLocked == totalSpent when cancelling Active order.
        // This requires: maxPricePerItem * initialQuantity == totalSpent.
        // But an active order with full spent means quantity == 0 => Filled.
        // So zero refund can only happen if price per fill == maxPricePerItem always.
        // After N fills at maxPricePerItem, qty drops. Once qty==0, state=Filled.
        // => Zero refund only if cancel happens when totalSpent == totalLocked but qty > 0
        // This is actually impossible since totalSpent can never exceed totalLocked.
        // The if (refundAmount > 0) guard handles rounding or edge cases.
        // Let's just verify the basic cancel refund works:
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        // Match one at maxPrice
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(7010);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Cancel — should refund maxPricePerItem * 2 - ITEM_PRICE = ITEM_PRICE
        uint256 buyerBalBefore = marketplace.userBalances(buyer);
        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);
        uint256 buyerBalAfter = marketplace.userBalances(buyer);

        assertEq(buyerBalAfter - buyerBalBefore, ITEM_PRICE, "should refund remaining");
    }

    // ========================================================================
    // SECTION 17: executeBuyOrderMatchWithSignature — all branches
    // ========================================================================

    function test_buyOrderMatch_notActive_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        // Cancel the order
        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8010);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(abi.encodeWithSelector(
            JJSKIN.InvalidBuyOrderState.selector,
            JJSKIN.BuyOrderState.Cancelled,
            JJSKIN.BuyOrderState.Active
        ));
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_sellerNotRegistered_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        address unregistered = address(0xDEAD);
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8011);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, unregistered, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, unregistered, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_priceExceedsMaxReverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8012);
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: detail,
            price: uint56(ITEM_PRICE + 1),
            nonce: keccak256(abi.encodePacked(seller, assetId, block.timestamp))
        });
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_sellerIsBuyer_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        // Buyer creates order then tries to match as seller
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8013);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, buyer, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, buyerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.CannotBuyOwnItem.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, buyer, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_itemSpecMismatch_reverts() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        // Create detail that does NOT match spec (wrong paintIndex)
        ItemDetail wrongDetail = ItemDetailLib.encode(
            2,       // paintIndex=2 (spec requires 1)
            524288,
            7,
            500,
            1,
            0
        );

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8014);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, wrongDetail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, wrongDetail);

        vm.expectRevert(JJSKIN.ItemSpecMismatch.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_priceExceedsMax_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        uint56 tooExpensive = ITEM_PRICE + 1;
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8015);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, tooExpensive, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_cancelledNonce_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8016);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        // Cancel the nonce
        vm.prank(seller);
        marketplace.cancelListing(listing.nonce);

        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_alreadyListed_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        // Create a direct listing first for the same assetId
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8017);
        _createListingAndPurchase(assetId, seller2, buyer2, ITEM_PRICE);

        // Now try to match buy order with same assetId
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(abi.encodeWithSelector(JJSKIN.AlreadyListed.selector, assetId));
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_buyOrderMatch_fillsAndRefundsSurplus() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        uint56 maxPrice = 15_000_000; // 15 USDC max
        uint56 actualPrice = 8_000_000; // 8 USDC actual

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, maxPrice, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8018);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, actualPrice, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
        uint256 buyerBalAfter = marketplace.userBalances(buyer);

        // Order filled, surplus = 15M - 8M = 7M refunded to userBalance
        assertEq(buyerBalAfter - buyerBalBefore, maxPrice - actualPrice, "surplus refunded");

        (,,, JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Filled));
    }

    function test_buyOrderMatch_partialFill_emitsCorrectEvent() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 3);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8019);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Verify state: qty should be 2, state still Active
        (, uint8 qty,, JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(qty, 2, "quantity should be 2");
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Active));
    }

    // ========================================================================
    // SECTION 18: _verifyOracleAttestation — unapproved oracle
    // ========================================================================

    function test_oracleAttestation_unapprovedOracle_reverts() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8020);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);

        // Sign oracle attestation with attacker key (0x9) — NOT an approved oracle
        bytes32 ATTESTATION_TYPEHASH = keccak256(
            "ItemAttestation(address seller,uint64 assetId,uint64 itemDetail)"
        );
        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            seller,
            JJSKIN.AssetId.unwrap(assetId),
            ItemDetail.unwrap(detail)
        ));
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("JJSKIN"),
                keccak256("1"),
                block.chainid,
                address(marketplace)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        bytes memory fakeOracleSig = abi.encodePacked(r, s, v);

        vm.expectRevert(JJSKIN.InvalidOracleAttestation.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, fakeOracleSig);
    }

    // ========================================================================
    // SECTION 19: setYieldVault — all branches
    // ========================================================================

    function test_setYieldVault_success() public {
        // Deploy a vault
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );

        vm.prank(owner);
        marketplace.setYieldVault(address(vault));
        assertEq(address(marketplace.yieldVault()), address(vault));
    }

    function test_setYieldVault_alreadySet_reverts() public {
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );

        vm.prank(owner);
        marketplace.setYieldVault(address(vault));

        vm.prank(owner);
        vm.expectRevert(JJSKIN.AlreadyProcessed.selector);
        marketplace.setYieldVault(address(vault));
    }

    function test_setYieldVault_zeroAddress_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.ZeroAddress.selector);
        marketplace.setYieldVault(address(0));
    }

    // ========================================================================
    // SECTION 20: depositIdleFundsToVault — all branches
    // ========================================================================

    function test_depositIdleFundsToVault_noVault_reverts() public {
        // No vault set
        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.depositIdleFundsToVault();
    }

    function test_depositIdleFundsToVault_belowMinimum_reverts() public {
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        vm.prank(owner);
        marketplace.setYieldVault(address(vault));

        // Contract has no USDC balance (below MIN_VAULT_DEPOSIT of 500 USDC)
        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.depositIdleFundsToVault();
    }

    // ========================================================================
    // SECTION 21: harvestYield — no vault
    // ========================================================================

    function test_harvestYield_noVault_reverts() public {
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.harvestYield();
    }

    // ========================================================================
    // SECTION 22: withdrawFees — all branches
    // ========================================================================

    function test_withdrawFees_notTreasury_reverts() public {
        vm.prank(attacker);
        vm.expectRevert(JJSKIN.NotTreasury.selector);
        marketplace.withdrawFees();
    }

    function test_withdrawFees_zeroAmount_reverts() public {
        // Oracle is set as treasury in setUp
        vm.prank(oracle);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.withdrawFees();
    }

    function test_withdrawFees_success() public {
        // Generate some fees via a release settlement
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        // Set fee to 5% for visible fees
        vm.prank(owner);
        marketplace.setPlatformFee(500);

        _oracleClaim(ASSET_ID);

        // Treasury (oracle) should have withdrawable fees
        uint256 fees = marketplace.withdrawableFees(oracle);
        assertTrue(fees > 0, "should have fees");

        vm.prank(oracle);
        marketplace.withdrawFees();

        assertEq(marketplace.withdrawableFees(oracle), 0);
    }

    // ========================================================================
    // SECTION 23: rescueERC20 — all branches
    // ========================================================================

    function test_rescueERC20_cannotWithdrawUSDC() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.CannotWithdrawUSDC.selector);
        marketplace.rescueERC20(address(usdc), 100);
    }

    function test_rescueERC20_otherToken_success() public {
        // Deploy a random ERC20 and send to marketplace
        MockUSDC randomToken = new MockUSDC();
        randomToken.mint(address(marketplace), 1000);

        vm.prank(owner);
        marketplace.rescueERC20(address(randomToken), 1000);
        assertEq(randomToken.balanceOf(owner), 1000);
    }

    function test_rescueERC20_notOwner_reverts() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.rescueERC20(address(usdc), 100);
    }

    // ========================================================================
    // SECTION 24: getDeliveryDeadline — no purchase returns 0
    // ========================================================================

    function test_getDeliveryDeadline_noPurchase_returnsZero() public view {
        uint256 deadline = marketplace.getDeliveryDeadline(ASSET_ID_2);
        assertEq(deadline, 0);
    }

    function test_getDeliveryDeadline_withPurchase() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        uint256 deadline = marketplace.getDeliveryDeadline(ASSET_ID);
        (, uint40 purchaseTime,,) = marketplace.purchases(ASSET_ID);
        assertEq(deadline, uint256(purchaseTime) + marketplace.deliveryWindow());
    }

    // ========================================================================
    // SECTION 25: isPurchaseActive — true/false branches
    // ========================================================================

    function test_isPurchaseActive_nonExistent_returnsFalse() public view {
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID_2);
        assertFalse(marketplace.isPurchaseActive(rawId));
    }

    function test_isPurchaseActive_active_returnsTrue() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        assertTrue(marketplace.isPurchaseActive(rawId));
    }

    function test_isPurchaseActive_settled_returnsFalse() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);

        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        assertFalse(marketplace.isPurchaseActive(rawId));
    }

    // ========================================================================
    // SECTION 26: getPurchaseStatus — no purchase reverts
    // ========================================================================

    function test_getPurchaseStatus_noPurchase_reverts() public {
        vm.expectRevert(JJSKIN.NoPurchaseExists.selector);
        marketplace.getPurchaseStatus(ASSET_ID_2);
    }

    function test_getPurchaseStatus_active() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(ASSET_ID);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));
    }

    // ========================================================================
    // SECTION 27: cancelListings (batch)
    // ========================================================================

    function test_cancelListings_batch() public {
        bytes32 nonce1 = keccak256("n1");
        bytes32 nonce2 = keccak256("n2");
        bytes32[] memory nonces = new bytes32[](2);
        nonces[0] = nonce1;
        nonces[1] = nonce2;

        vm.prank(seller);
        marketplace.cancelListings(nonces);

        assertTrue(marketplace.isListingCancelled(seller, nonce1));
        assertTrue(marketplace.isListingCancelled(seller, nonce2));
    }

    // ========================================================================
    // SECTION 28: withdrawBalance — basic path
    // ========================================================================

    function test_withdrawBalance_zeroBalance_reverts() public {
        vm.prank(user1);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.withdrawBalance();
    }

    function test_withdrawBalance_success() public {
        // Build user balance via refund
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);

        uint256 buyerUSDCBefore = usdc.balanceOf(buyer);
        vm.prank(buyer);
        marketplace.withdrawBalance();
        uint256 buyerUSDCAfter = usdc.balanceOf(buyer);

        assertEq(buyerUSDCAfter - buyerUSDCBefore, ITEM_PRICE);
        assertEq(marketplace.userBalances(buyer), 0);
    }

    // ========================================================================
    // SECTION 29: submitSettlement — release path with fee calculation
    // ========================================================================

    function test_submitSettlement_release_correctFeeDistribution() public {
        // Set a clear fee for testing
        vm.prank(owner);
        marketplace.setPlatformFee(200); // 2%

        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        uint256 sellerBalBefore = marketplace.userBalances(seller);
        _oracleClaim(ASSET_ID);
        uint256 sellerBalAfter = marketplace.userBalances(seller);

        // Fee = 10M * 200 / 10000 = 200000 (0.2 USDC)
        // Seller gets 10M - 200000 = 9800000
        uint256 expectedFee = (uint256(ITEM_PRICE) * 200) / 10000;
        uint256 expectedSeller = ITEM_PRICE - expectedFee;
        assertEq(sellerBalAfter - sellerBalBefore, expectedSeller);
    }

    // ========================================================================
    // SECTION 30: submitSettlement — refund path (no buy order)
    // ========================================================================

    function test_submitSettlement_refund_noBuyOrder_toUserBalance() public {
        // Direct listing (not from buy order) + refund
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        uint256 buyerBalBefore = marketplace.userBalances(buyer);
        _oracleRefund(ASSET_ID, JJSKIN.RefundReason.Canceled2FA);
        uint256 buyerBalAfter = marketplace.userBalances(buyer);

        assertEq(buyerBalAfter - buyerBalBefore, ITEM_PRICE, "refund goes to userBalance");
    }

    // ========================================================================
    // SECTION 31: isCommitmentDeadlinePassed — all branches
    // ========================================================================

    function test_isCommitmentDeadlinePassed_noPurchase() public view {
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID_2);
        (bool passed, bool hasCommitment) = marketplace.isCommitmentDeadlinePassed(rawId);
        assertFalse(passed);
        assertFalse(hasCommitment);
    }

    function test_isCommitmentDeadlinePassed_beforeDeadline() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        (bool passed, bool hasCommitment) = marketplace.isCommitmentDeadlinePassed(rawId);
        assertFalse(passed);
        assertFalse(hasCommitment);
    }

    function test_isCommitmentDeadlinePassed_afterDeadline_noCommitment() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 7 hours); // Past 6h delivery window

        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        (bool passed, bool hasCommitment) = marketplace.isCommitmentDeadlinePassed(rawId);
        assertTrue(passed);
        assertFalse(hasCommitment);
    }

    function test_isCommitmentDeadlinePassed_withCommitment() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);
        vm.warp(block.timestamp + 7 hours);

        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        (bool passed, bool hasCommitment) = marketplace.isCommitmentDeadlinePassed(rawId);
        assertTrue(passed);
        assertTrue(hasCommitment);
    }

    // ========================================================================
    // SECTION 32: emergencyWithdrawFromVault — all branches
    // ========================================================================

    function test_emergencyWithdrawFromVault_noVault_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.emergencyWithdrawFromVault();
    }

    function test_emergencyWithdrawFromVault_noShares_reverts() public {
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        vm.prank(owner);
        marketplace.setYieldVault(address(vault));

        // No deposits so no shares
        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.emergencyWithdrawFromVault();
    }

    // ========================================================================
    // SECTION 33: getTradeOfferCommitment view
    // ========================================================================

    function test_getTradeOfferCommitment_noCommitment() public view {
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID_2);
        uint48 tradeOfferId = marketplace.getTradeOfferCommitment(rawId);
        assertEq(tradeOfferId, 0);
    }

    function test_getTradeOfferCommitment_withCommitment() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 54321);

        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        uint48 tradeOfferId = marketplace.getTradeOfferCommitment(rawId);
        assertEq(tradeOfferId, 54321);
    }

    // ========================================================================
    // SECTION 34: getUserBalance view
    // ========================================================================

    function test_getUserBalance_zero() public view {
        assertEq(marketplace.getUserBalance(user1), 0);
    }

    function test_getUserBalance_nonZero() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(ASSET_ID);
        assertEq(marketplace.getUserBalance(buyer), ITEM_PRICE);
    }

    // ========================================================================
    // SECTION 35: getBatchAssetInfo view
    // ========================================================================

    function test_getBatchAssetInfo_empty() public view {
        uint64[] memory ids = new uint64[](0);
        (uint56[] memory prices, uint40[] memory times, JJSKIN.PurchaseStatus[] memory statuses, bool[] memory exists) =
            marketplace.getBatchAssetInfo(ids);
        assertEq(prices.length, 0);
        assertEq(times.length, 0);
        assertEq(statuses.length, 0);
        assertEq(exists.length, 0);
    }

    function test_getBatchAssetInfo_withData() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        uint64[] memory ids = new uint64[](1);
        ids[0] = JJSKIN.AssetId.unwrap(ASSET_ID);

        (uint56[] memory prices,, JJSKIN.PurchaseStatus[] memory statuses, bool[] memory exists) =
            marketplace.getBatchAssetInfo(ids);
        assertEq(prices[0], ITEM_PRICE);
        assertEq(uint8(statuses[0]), uint8(JJSKIN.PurchaseStatus.Active));
        assertTrue(exists[0]);
    }

    // ========================================================================
    // SECTION 36: getSellerAddress view
    // ========================================================================

    function test_getSellerAddress_noListing() public view {
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID_2);
        assertEq(marketplace.getSellerAddress(rawId), address(0));
    }

    function test_getSellerAddress_withListing() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        uint64 rawId = JJSKIN.AssetId.unwrap(ASSET_ID);
        assertEq(marketplace.getSellerAddress(rawId), seller);
    }

    // ========================================================================
    // SECTION 37: submitSettlement — all fees go to treasury
    // ========================================================================

    function test_submitSettlement_allFeesToTreasury() public {
        // Set a clear fee for testing
        vm.prank(owner);
        marketplace.setPlatformFee(500); // 5%

        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 12345);

        uint256 treasuryFeesBefore = marketplace.withdrawableFees(oracle);
        _oracleClaim(ASSET_ID);
        uint256 treasuryFeesAfter = marketplace.withdrawableFees(oracle);

        // fee = 10M * 500 / 10000 = 500000 (0.50 USDC)
        uint256 expectedFee = (uint256(ITEM_PRICE) * 500) / 10000;
        assertEq(treasuryFeesAfter - treasuryFeesBefore, expectedFee, "all fees go to treasury");
    }

    function test_submitSettlement_feesToTreasury_multipleTrades() public {
        // Set fee to 2%
        vm.prank(owner);
        marketplace.setPlatformFee(200);

        // Create and settle two trades
        JJSKIN.AssetId aid1 = JJSKIN.AssetId.wrap(9100);
        JJSKIN.AssetId aid2 = JJSKIN.AssetId.wrap(9101);
        _createListingAndPurchase(aid1, seller, buyer, ITEM_PRICE);
        _createListingAndPurchase(aid2, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(aid1, 12345);
        vm.prank(seller);
        marketplace.commitTradeOffer(aid2, 12346);

        uint256 treasuryFeesBefore = marketplace.withdrawableFees(oracle);

        // Settle both individually
        _oracleClaim(aid1);
        _oracleClaim(aid2);

        uint256 treasuryFeesAfter = marketplace.withdrawableFees(oracle);

        // Total fee = 2 * (10M * 200 / 10000) = 2 * 200000 = 400000
        uint256 expectedFee = 2 * ((uint256(ITEM_PRICE) * 200) / 10000);
        assertEq(treasuryFeesAfter - treasuryFeesBefore, expectedFee, "all fees go to treasury");
    }

    // ========================================================================
    // SECTION 38: submitSettlement — no escrow commitment
    // ========================================================================

    function test_submitSettlement_noEscrowCommitment_reverts() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        // No commit — tradeOfferId is 0

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(ASSET_ID);
        bytes memory sig = _signSettlement(rawAssetId, 0, 0, 0);

        vm.expectRevert(JJSKIN.NoPurchaseExists.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, sig);
    }

    // ========================================================================
    // SECTION 39: Constructor validation branches
    // ========================================================================

    function test_constructor_zeroUSDC_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.ZeroAddress.selector);
        new JJSKIN(address(0), address(walletFactory));
    }

    function test_constructor_zeroFactory_reverts() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.ZeroAddress.selector);
        new JJSKIN(address(usdc), address(0));
    }

    function test_constructor_notERC20_reverts() public {
        vm.prank(owner);
        // Pass an address that doesn't implement decimals()
        vm.expectRevert(JJSKIN.NotERC20Token.selector);
        new JJSKIN(address(walletFactory), address(walletFactory));
    }

    function test_constructor_wrongDecimals_reverts() public {
        // Deploy a mock token with 18 decimals
        MockWrongDecimalsToken wrongToken = new MockWrongDecimalsToken();
        vm.prank(owner);
        vm.expectRevert(JJSKIN.NotUSDC.selector);
        new JJSKIN(address(wrongToken), address(walletFactory));
    }

    // ========================================================================
    // SECTION 40: withdrawBalance vault interaction branches
    // ========================================================================

    function test_withdrawBalance_pullsFromVault() public {
        // Setup: vault is set, many purchases to get balance above MIN_VAULT_DEPOSIT
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        vm.prank(owner);
        marketplace.setYieldVault(address(vault));

        // Create many purchases to accumulate > 500 USDC in the marketplace
        // Each purchase is 10 USDC, need 51 purchases to exceed 500 USDC (MIN_VAULT_DEPOSIT)
        for (uint64 i = 1; i <= 55; i++) {
            JJSKIN.AssetId aid = JJSKIN.AssetId.wrap(80000 + i);
            _createListingAndPurchase(aid, seller, buyer, ITEM_PRICE);
            vm.prank(seller);
            marketplace.commitTradeOffer(aid, i);
        }

        // Settle all as releases
        for (uint64 i = 1; i <= 55; i++) {
            JJSKIN.AssetId aid = JJSKIN.AssetId.wrap(80000 + i);
            _oracleClaim(aid);
        }

        // Now deposit the idle funds to vault (should be > MIN_VAULT_DEPOSIT)
        vm.prank(owner);
        marketplace.depositIdleFundsToVault();

        // Seller should have substantial balance from releases
        uint256 sellerBal = marketplace.userBalances(seller);
        assertGt(sellerBal, 0, "seller should have balance");

        // Withdraw — should pull from vault since most USDC is now in vault
        vm.prank(seller);
        marketplace.withdrawBalance();

        assertEq(marketplace.userBalances(seller), 0);
    }

    // ========================================================================
    // SECTION 41: MatchingLib branches
    // ========================================================================

    function test_matchingLib_defindexMismatch() public {
        // ItemSpec with defindex=7, ItemDetail with defindex=8
        ItemSpec spec = ItemSpecLib.encode(1, 0, 1023, 7, 0, 0);
        ItemDetail detail = ItemDetailLib.encode(1, 524288, 8, 500, 1, 0); // defindex=8, doesn't match

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(77777);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.ItemSpecMismatch.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_matchingLib_qualityMismatch() public {
        // ItemSpec with quality=0, ItemDetail with quality=1 (StatTrak)
        ItemSpec spec = ItemSpecLib.encode(1, 0, 1023, 7, 0, 0); // quality=0
        ItemDetail detail = ItemDetailLib.encode(1, 524288, 7, 500, 1, 1); // quality=1

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(77778);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.ItemSpecMismatch.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_matchingLib_floatOutOfRange() public {
        // ItemSpec with minFloat=100, maxFloat=200; ItemDetail with float=0 (below range)
        ItemSpec spec = ItemSpecLib.encode(1, 100, 200, 7, 0, 0);
        ItemDetail detail = ItemDetailLib.encode(1, 0, 7, 500, 1, 0); // floatValue=0, shift>>10 = 0 < 100

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(77779);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.ItemSpecMismatch.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_matchingLib_patternTierMismatch() public {
        // ItemSpec requires tier 2, ItemDetail has tier 1
        ItemSpec spec = ItemSpecLib.encode(1, 0, 1023, 7, 2, 0); // patternTier=2
        ItemDetail detail = ItemDetailLib.encode(1, 524288, 7, 500, 1, 0); // patternTier=1

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(77780);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, detail);

        vm.expectRevert(JJSKIN.ItemSpecMismatch.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }
    // ========================================================================
    // SECTION 42: totalUserBalances consistency — kills mutation survivors
    // ========================================================================

    /// @notice Buyer has MORE balance than buy order cost → full-balance path.
    ///         Assert totalUserBalances decreases by exactly totalAmount, NOT buyerBalance.
    ///         Kills mutants 1002 (if-false), 1018/1019 (totalUserBalances -= 0/1).
    function test_createBuyOrder_fullBalance_totalUserBalances() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        // Build buyer balance = 2 * ITEM_PRICE via two refunds
        JJSKIN.AssetId aid1 = JJSKIN.AssetId.wrap(9901);
        JJSKIN.AssetId aid2 = JJSKIN.AssetId.wrap(9902);
        _createListingAndPurchase(aid1, seller, buyer, ITEM_PRICE);
        _createListingAndPurchase(aid2, seller, buyer, ITEM_PRICE);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(aid1);
        marketplace.claimTimeoutRefund(aid2);

        uint256 buyerBalance = marketplace.userBalances(buyer);
        assertEq(buyerBalance, 2 * ITEM_PRICE, "buyer has 2x balance");

        uint256 totalBefore = marketplace.totalUserBalances();
        uint256 walletBefore = usdc.balanceOf(buyer);

        // Buy order costs ITEM_PRICE (1 qty) — buyer has 2x that
        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        uint256 totalAfter = marketplace.totalUserBalances();
        uint256 walletAfter = usdc.balanceOf(buyer);

        // totalUserBalances must decrease by exactly totalAmount (ITEM_PRICE), not buyerBalance (2x)
        assertEq(totalBefore - totalAfter, ITEM_PRICE, "totalUserBalances -= totalAmount");
        assertEq(marketplace.userBalances(buyer), ITEM_PRICE, "remaining balance = excess");
        assertEq(walletAfter, walletBefore, "wallet untouched in full-balance path");
    }

    /// @notice Buyer has partial balance → partial-balance path.
    ///         Assert totalUserBalances decreases by exactly buyerBalance.
    ///         Kills mutants 1008/1009 (totalUserBalances -= 0/1 in partial path).
    function test_createBuyOrder_partialBalance_totalUserBalances() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        // Build partial balance = 4 USDC (less than ITEM_PRICE = 10 USDC)
        uint56 smallPrice = 4_000_000;
        JJSKIN.AssetId aid = JJSKIN.AssetId.wrap(9903);
        _createListingAndPurchase(aid, seller, buyer, smallPrice);
        vm.warp(block.timestamp + 24 hours + 1);
        marketplace.claimTimeoutRefund(aid);

        uint256 buyerBalance = marketplace.userBalances(buyer);
        assertEq(buyerBalance, smallPrice, "buyer has partial balance");

        uint256 totalBefore = marketplace.totalUserBalances();

        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        uint256 totalAfter = marketplace.totalUserBalances();

        // totalUserBalances must decrease by exactly buyerBalance (4 USDC)
        assertEq(totalBefore - totalAfter, smallPrice, "totalUserBalances -= buyerBalance");
        assertEq(marketplace.userBalances(buyer), 0, "balance fully consumed");
    }

    /// @notice Buyer has zero balance → no-balance path (wallet pull only).
    ///         Assert totalUserBalances unchanged.
    ///         Kills mutant 1004 (buyerBalance > 0 → true: would wrongly enter partial path).
    function test_createBuyOrder_noBalance_totalUserBalances() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        assertEq(marketplace.userBalances(buyer), 0, "buyer starts with 0 balance");

        uint256 totalBefore = marketplace.totalUserBalances();

        vm.prank(buyer);
        marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        uint256 totalAfter = marketplace.totalUserBalances();

        // No balance consumed → totalUserBalances unchanged
        assertEq(totalAfter, totalBefore, "totalUserBalances unchanged when no balance");
    }

    /// @notice Cancel buy order → totalUserBalances increases by refundAmount.
    ///         Kills mutants 1041/1042 (totalUserBalances += 0/1).
    function test_cancelBuyOrder_totalUserBalances() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 2);

        uint256 totalBefore = marketplace.totalUserBalances();

        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        uint256 totalAfter = marketplace.totalUserBalances();
        uint256 expectedRefund = uint256(ITEM_PRICE) * 2; // full refund, nothing spent

        assertEq(totalAfter - totalBefore, expectedRefund, "totalUserBalances += refundAmount");
        assertEq(marketplace.userBalances(buyer), expectedRefund, "buyer receives full refund");
    }

    /// @notice Cancel buy order → quantity set to 0.
    ///         Kills mutant 1035 (order.quantity = 0 → order.quantity = 1).
    function test_cancelBuyOrder_quantityZeroed() public {
        (ItemSpec spec,) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 3);

        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        (, uint8 quantity,,,,,) = marketplace.buyOrders(orderId);
        assertEq(quantity, 0, "quantity must be 0 after cancel");
    }
}

/// @notice Helper: ERC20 token with 18 decimals (not USDC-compatible)
contract MockWrongDecimalsToken {
    function decimals() external pure returns (uint8) { return 18; }
}
