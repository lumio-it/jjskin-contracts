// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";
import "../../src/CS2AaveVault.sol";

/// @title Settlement & Admin Regression Tests
/// @notice Tests for correct behavior of settlement validation, treasury management,
///         vault access control, and buy order price validation
contract SettlementRegressionTest is BaseTest {

    function setUp() public override {
        super.setUp();
    }

    // ========================================================================
    // Treasury: fee migration on treasury change
    // ========================================================================

    function test_setTreasury_migratesPendingFees() public {
        // Generate fees via a release settlement
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);
        _oracleClaim(ASSET_ID);

        address oldTreasury = marketplace.treasury();
        uint256 pendingFees = marketplace.withdrawableFees(oldTreasury);
        assertGt(pendingFees, 0);

        // Change treasury
        address newTreasury = address(0xBEEF);
        vm.prank(owner);
        marketplace.setTreasury(newTreasury);

        // Old treasury zeroed, new treasury inherited
        assertEq(marketplace.withdrawableFees(oldTreasury), 0);
        assertEq(marketplace.withdrawableFees(newTreasury), pendingFees);

        // New treasury can withdraw
        vm.prank(newTreasury);
        marketplace.withdrawFees();
        assertEq(marketplace.withdrawableFees(newTreasury), 0);
    }

    // ========================================================================
    // Buy order match: price must be > 0
    // ========================================================================

    function test_buyOrderMatch_rejectsZeroPrice() public {
        (ItemSpec spec, ItemDetail detail) = _createMatchingItemPair();
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);

        JJSKIN.AssetId zeroAssetId = JJSKIN.AssetId.wrap(99999);
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: zeroAssetId,
            itemDetail: detail,
            price: 0,
            nonce: keccak256(abi.encodePacked(seller, zeroAssetId, block.timestamp))
        });

        bytes memory sellerSig = _signListing(listing, sellerKey);
        bytes memory oracleAttestation = _signOracleAttestation(zeroAssetId, detail);

        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.executeBuyOrderMatchWithSignature(
            orderId, listing, seller, sellerSig, oracleAttestation
        );
    }

    // ========================================================================
    // Settlement: decision must be 0 or 1
    // ========================================================================

    function test_submitSettlement_rejectsInvalidDecision() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        uint64 raw = JJSKIN.AssetId.unwrap(ASSET_ID);
        (,,, uint48 tradeOfferId) = marketplace.purchases(ASSET_ID);
        bytes memory sig = _signSettlement(raw, tradeOfferId, 5, 0);

        vm.expectRevert(abi.encodeWithSelector(JJSKIN.InvalidSettlementType.selector, uint8(5)));
        marketplace.submitSettlement(raw, 5, 0, sig);
    }

    // ========================================================================
    // Settlement: release (decision=0) must have refundReason=0
    // ========================================================================

    function test_submitSettlement_rejectsReleaseWithRefundReason() public {
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        uint64 raw = JJSKIN.AssetId.unwrap(ASSET_ID);
        (,,, uint48 tradeOfferId) = marketplace.purchases(ASSET_ID);
        bytes memory sig = _signSettlement(raw, tradeOfferId, 0, 5);

        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.submitSettlement(raw, 0, 5, sig);
    }

    // ========================================================================
    // Settlement: signature replay blocked after refund + relist
    // ========================================================================

    function test_submitSettlement_replayBlockedAfterRelist() public {
        // First purchase -> refund
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        uint64 raw = JJSKIN.AssetId.unwrap(ASSET_ID);
        bytes memory oldRefundSig = _signSettlement(raw, 1001, 1, uint8(JJSKIN.RefundReason.BuyerCanceled));
        marketplace.submitSettlement(raw, 1, uint8(JJSKIN.RefundReason.BuyerCanceled), oldRefundSig);

        // Re-list same assetId -> new purchase with different tradeOfferId
        JJSKIN.ListingData memory listing2 = JJSKIN.ListingData({
            assetId: ASSET_ID,
            itemDetail: ItemDetail.wrap(0),
            price: ITEM_PRICE,
            nonce: keccak256(abi.encodePacked(seller, ASSET_ID, block.timestamp + 1))
        });
        bytes memory sig2 = _signListing(listing2, sellerKey);
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing2, seller, sig2);

        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 2002);

        // Old signature (tradeOfferId=1001) rejected on new purchase (tradeOfferId=2002)
        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(raw, 1, uint8(JJSKIN.RefundReason.BuyerCanceled), oldRefundSig);

        // Purchase still Active
        assertEq(uint8(marketplace.getPurchaseStatus(ASSET_ID)), uint8(JJSKIN.PurchaseStatus.Active));
    }

    // ========================================================================
    // Vault: depositIdleFundsToVault requires owner
    // ========================================================================

    function test_depositIdleFundsToVault_requiresOwner() public {
        vm.startPrank(owner);
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)), IPool(address(aavePool)), IAToken(address(aToken)), address(marketplace), owner
        );
        marketplace.setYieldVault(address(vault));
        vm.stopPrank();

        _createListingAndPurchase(ASSET_ID, seller, buyer, 600_000_000);

        // Non-owner reverts
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.depositIdleFundsToVault();

        // Owner succeeds
        vm.prank(owner);
        marketplace.depositIdleFundsToVault();
    }

    // ========================================================================
    // Vault: withdrawBalance pulls from vault correctly
    // ========================================================================

    function test_withdrawBalance_pullsFromVault() public {
        vm.startPrank(owner);
        CS2AaveVault vault = new CS2AaveVault(
            IERC20(address(usdc)), IPool(address(aavePool)), IAToken(address(aToken)), address(marketplace), owner
        );
        marketplace.setYieldVault(address(vault));
        vm.stopPrank();

        // Settle to give seller a balance
        _createListingAndPurchase(ASSET_ID, seller, buyer, 600_000_000);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);
        _oracleClaim(ASSET_ID);

        uint256 sellerBal = marketplace.userBalances(seller);
        assertGt(sellerBal, 0);

        // Deposit to vault so contract USDC < seller balance
        vm.prank(owner);
        marketplace.depositIdleFundsToVault();

        // Seller can still withdraw (pulls from vault)
        vm.prank(seller);
        marketplace.withdrawBalance();
        assertEq(marketplace.userBalances(seller), 0);
    }

    // ========================================================================
    // getBatchAssetInfo: exists flag distinguishes real vs non-existent
    // ========================================================================

    function test_getBatchAssetInfo_existsFlag() public {
        // Create one real purchase
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);

        uint64[] memory ids = new uint64[](2);
        ids[0] = JJSKIN.AssetId.unwrap(ASSET_ID); // real
        ids[1] = 999999; // never purchased

        (,,, bool[] memory exists) = marketplace.getBatchAssetInfo(ids);

        assertTrue(exists[0], "Real purchase should exist");
        assertFalse(exists[1], "Non-existent purchase should not exist");
    }
}
