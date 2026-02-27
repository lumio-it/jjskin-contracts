// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "./base/BaseTest.sol";
import {JJSKIN, ItemDetail, ItemSpec} from "../src/JJSKIN.sol";
import {CS2AaveVault, IPool, IAToken} from "../src/CS2AaveVault.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title JJSKIN Security Test Suite
 * @notice Tests focusing on security aspects:
 *         - Access control
 *         - Reentrancy protection
 *         - Input validation
 *         - Oracle access control (TEE oracle model)
 *         - Vault security
 */
contract JJSKINSecurityTest is BaseTest {
    // Additional test-specific variables
    CS2AaveVault public vault;
    address public feeRecipient;

    uint256 constant PRICE = 100 * 1e6;

    function setUp() public override {
        super.setUp();

        feeRecipient = oracle; // Fees now go to oracle (VerifierNetwork)

        // Deploy vault
        vm.startPrank(owner);
        vault = new CS2AaveVault(
            IERC20(address(usdcToken)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        marketplace.setYieldVault(address(vault));

        // Fund users (still as owner of USDC)
        _fundUser(seller, 1000 * 1e6);
        _fundUser(buyer, 1000 * 1e6);
        _fundUser(attacker, 1000 * 1e6);

        vm.stopPrank();

        // Setup users
        _registerUser(seller, 1);
        _registerUser(buyer, 2);
        _registerUser(attacker, 3);

        vm.prank(buyer);
        usdcToken.approve(address(marketplace), type(uint256).max);
        vm.prank(attacker);
        usdcToken.approve(address(marketplace), type(uint256).max);
    }

    // ========== Helper Functions ==========

    function _getSignature(JJSKIN.ListingData memory listing, address signer) internal view returns (bytes memory) {
        uint256 signerKey;
        if (signer == seller) signerKey = sellerKey;
        else if (signer == seller2) signerKey = seller2Key;
        else if (signer == buyer) signerKey = buyerKey;
        else if (signer == buyer2) signerKey = buyer2Key;
        else if (signer == attacker) signerKey = attackerKey;
        else revert("Unknown signer");

        return _signListing(listing, signerKey);
    }

    // ========== Access Control Tests ==========

    function test_OnlyOwnerCanSetTimeWindows() public {
        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setDeliveryWindow(12 hours);

        vm.prank(attacker);
        vm.expectRevert();
        marketplace.setAbandonedWindow(48 hours);

        // Owner can set
        vm.startPrank(owner);
        marketplace.setDeliveryWindow(12 hours);
        marketplace.setAbandonedWindow(48 hours);
        vm.stopPrank();
    }

    function test_OnlyOracleSignatureCanSettle() public {
        // Only oracle-signed settlements are accepted; invalid signatures revert
        JJSKIN.AssetId assetId = _createPurchase();

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(assetId);

        // Sign with attacker key (not oracle)
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Settlement(uint64 assetId,uint8 decision,uint8 refundReason)"),
            rawAssetId, uint8(1), uint8(JJSKIN.RefundReason.Timeout)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        bytes memory attackerSig = abi.encodePacked(r, s, v);

        // Attacker-signed settlement should revert
        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(rawAssetId, 1, uint8(JJSKIN.RefundReason.Timeout), attackerSig);

        // Oracle-signed settlement should succeed (anyone can submit)
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_OracleSettlement_OracleCanRefund() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // Oracle can refund
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_OracleSettlement_OracleCanRelease() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // Oracle can release
        _oracleClaim(assetId);

        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Released));
    }

    // ========== Reentrancy Tests ==========
    // NOTE: Reentrancy protection is implemented via nonReentrant modifier on all external functions
    // Since the marketplace uses ERC20 (USDC) and not ETH, traditional reentrancy attacks
    // via receive() or fallback() are not possible. The nonReentrant modifier prevents
    // any form of reentrancy through external contract calls.

    // ========== Input Validation Tests ==========

    function test_RevertZeroPriceListing() public {
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(uint64(1)),
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: 0,
            nonce: keccak256(abi.encode(block.timestamp))
        });

        bytes memory signature = _getSignature(listing, seller);

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    function test_RevertInvalidTimeWindows() public {
        vm.startPrank(owner);

        // Delivery window too short
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(30 minutes);

        // Delivery window too long
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(49 hours);

        // Abandoned window too short
        vm.expectRevert("Invalid abandoned window");
        marketplace.setAbandonedWindow(11 hours);

        vm.stopPrank();
    }

    function test_RevertExcessivePlatformFee() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(
            JJSKIN.FeeExceedsMaximum.selector,
            600,
            500
        ));
        marketplace.setPlatformFee(600); // 6% exceeds 5% max
    }

    // ========== Oracle Trust Model Tests ==========
    // NOTE: All timing verification now happens off-chain via TLSNotary proofs
    // Oracle is trusted to only call functions after proper verification

    function test_OracleCanRefundAnytime() public {
        // Oracle is trusted - can refund immediately after purchase if needed
        JJSKIN.AssetId assetId = _createPurchase();

        // Oracle can refund immediately (verified off-chain)
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_OracleCanReleaseAnytime() public {
        // Oracle is trusted - can release funds immediately after verifying trade
        JJSKIN.AssetId assetId = _createPurchase();

        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        // Oracle can release immediately (verified off-chain via TLSNotary)
        _batchReleaseFunds(assetIds);

        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Released));
    }

    // ========== Oracle State Validation Tests ==========

    function test_OracleCannotDoubleRelease() public {
        JJSKIN.AssetId assetId = _createPurchase();

        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // Record seller balance after first release
        uint256 sellerBalanceAfterFirst = marketplace.userBalances(seller);

        // Second release attempt - contract is now idempotent (skips already-settled)
        // Second release attempt should be skipped (idempotent), not revert
        _oracleClaim(assetId);

        // Verify balance unchanged (no double credit - was skipped)
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterFirst, "Seller balance should not change on double release");

        // Status should still be Released
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Released));
    }

    function test_OracleCannotDoubleRefund() public {
        JJSKIN.AssetId assetId = _createPurchase();

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record buyer balance after first refund
        uint256 buyerBalanceAfterRefund = marketplace.userBalances(buyer);

        // Second refund attempt - contract is now idempotent (skips already-settled)
        // Second refund attempt should be skipped (idempotent), not revert
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify buyer balance unchanged (no double refund - was skipped)
        assertEq(marketplace.userBalances(buyer), buyerBalanceAfterRefund, "Balance should not change on double refund");
    }

    function test_OracleCannotRefundAfterRelease() public {
        JJSKIN.AssetId assetId = _createPurchase();

        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // Record balances after release
        uint256 sellerBalanceAfterRelease = marketplace.userBalances(seller);
        uint256 buyerBalanceAfterRelease = marketplace.userBalances(buyer);

        // Refund attempt - contract is now idempotent (skips already-settled)
        // Refund attempt should be skipped (idempotent), not revert
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify balances unchanged (was skipped)
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterRelease, "Seller balance should not change");
        assertEq(marketplace.userBalances(buyer), buyerBalanceAfterRelease, "Buyer should not get refund after release");
    }

    function test_OracleCannotReleaseAfterRefund() public {
        JJSKIN.AssetId assetId = _createPurchase();

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record seller balance after refund (should be 0 - refund goes to buyer)
        uint256 sellerBalanceAfterRefund = marketplace.userBalances(seller);

        // Release attempt - contract is now idempotent (skips already-settled)
        // Release attempt should be skipped (idempotent), not revert
        _oracleClaim(assetId);

        // Verify seller balance unchanged (no credit after refund - was skipped)
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterRefund, "Seller should not receive funds after refund");

        // Status should still be Refunded
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    // ========== Vault Security Tests ==========

    function test_OnlyOwnerCanSetVault() public {
        JJSKIN newMarketplace = new JJSKIN(
            address(usdcToken),
            address(walletFactory)
        );
        newMarketplace.setTreasury(oracle);

        address newVault = makeAddr("newVault");

        vm.prank(attacker);
        vm.expectRevert();
        newMarketplace.setYieldVault(newVault);

        newMarketplace.setYieldVault(newVault);
        assertEq(address(newMarketplace.yieldVault()), newVault);
    }

    function test_CannotSetVaultTwice() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.AlreadyProcessed.selector);
        marketplace.setYieldVault(makeAddr("anotherVault"));
    }

    function test_VaultEmergencyMode() public {
        // Fund contract with enough USDC to meet minimum threshold
        uint256 minDeposit = marketplace.MIN_VAULT_DEPOSIT();
        vm.startPrank(owner);
        usdc.mint(address(marketplace), minDeposit);
        marketplace.depositIdleFundsToVault();

        // Activate emergency mode
        vault.activateEmergencyMode();
        vm.stopPrank();

        // Vault should withdraw all from Aave
        assertEq(aToken.balanceOf(address(vault)), 0);

        // Cannot deposit in emergency mode (need to add more funds first)
        vm.startPrank(owner);
        usdc.mint(address(marketplace), minDeposit);
        vm.expectRevert(CS2AaveVault.EmergencyModeActive.selector);
        marketplace.depositIdleFundsToVault();
        vm.stopPrank();
    }

    // ========== Signature Security Tests ==========

    function test_CannotReuseNonce() public {
        bytes32 nonce = keccak256(abi.encode(block.timestamp));

        JJSKIN.ListingData memory listing1 = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(uint64(1)),
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: nonce
        });

        bytes memory signature = _getSignature(listing1, seller);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing1, seller, signature);

        // Try to reuse nonce with different listing
        JJSKIN.ListingData memory listing2 = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(uint64(2)),
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: nonce // Same nonce
        });

        bytes memory signature2 = _getSignature(listing2, seller);

        vm.prank(buyer);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(listing2, seller, signature2);
    }

    function test_CannotBuyOwnItem() public {
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(uint64(1)),
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp))
        });

        bytes memory signature = _getSignature(listing, seller);

        vm.prank(seller);
        vm.expectRevert(JJSKIN.CannotBuyOwnItem.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    // ========== Factory Registration Tests ==========

    function test_RequiresFactoryWalletForPurchase() public {
        address unregistered = makeAddr("unregistered");
        vm.prank(owner);
        _fundUser(unregistered, 1000 * 1e6);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(uint64(1)),
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp))
        });

        bytes memory signature = _getSignature(listing, seller);

        vm.prank(unregistered);
        usdcToken.approve(address(marketplace), type(uint256).max);

        vm.prank(unregistered);
        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }

    function test_RequiresFactoryWalletForBuyOrder() public {
        address unregistered = makeAddr("unregistered");
        vm.prank(owner);
        _fundUser(unregistered, 1000 * 1e6);

        vm.prank(unregistered);
        usdcToken.approve(address(marketplace), type(uint256).max);

        vm.prank(unregistered);
        vm.expectRevert(JJSKIN.NotRegistered.selector);
        marketplace.createBuyOrder(
            ItemSpec.wrap(uint64(123)),
            uint56(PRICE),
            1
        );
    }

    function test_NonOracleSignatureCannotSettle() public {
        // Verify that non-oracle-signed settlements are rejected
        JJSKIN.AssetId assetId = _createPurchase();

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(assetId);

        // Sign with attacker key
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Settlement(uint64 assetId,uint8 decision,uint8 refundReason)"),
            rawAssetId, uint8(0), uint8(0)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        bytes memory attackerSig = abi.encodePacked(r, s, v);

        // Attacker-signed settlement should revert
        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, attackerSig);

        // Status should remain Active
        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Active));
    }

    // ========== Oracle Attestation Security Tests ==========

    function test_BuyOrderMatch_RejectsUnapprovedOracle() public {
        (ItemSpec itemSpec, ItemDetail itemDetail) = _createMatchingItemPair();

        // Fund and register seller2 for this test
        _registerUser(seller2, 76561198000000005);
        vm.prank(owner);
        _fundUser(seller2, 1000 * 1e6);

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(itemSpec, uint56(PRICE), 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(50));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });
        bytes memory sellerSig = _getSignature(listing, seller);

        // Sign attestation with attacker's key (not the registered oracle)
        bytes32 structHash = keccak256(abi.encode(
            ITEM_ATTESTATION_TYPEHASH,
            seller,
            JJSKIN.AssetId.unwrap(assetId),
            ItemDetail.unwrap(itemDetail)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"),
            keccak256("1"),
            block.chainid,
            address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        bytes memory fakeOracleSig = abi.encodePacked(r, s, v);

        vm.expectRevert(JJSKIN.InvalidOracleAttestation.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, fakeOracleSig);
    }

    function test_BuyOrderMatch_RejectsAfterOracleReRegistered() public {
        (ItemSpec itemSpec, ItemDetail itemDetail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(itemSpec, uint56(PRICE), 1);

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(51));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });
        bytes memory sellerSig = _getSignature(listing, seller);

        // Sign with the current oracle key
        bytes memory oracleSig = _signOracleAttestation(assetId, itemDetail);

        // Revoke the oracle, invalidating its signatures
        vm.prank(owner);
        marketplace.revokeOracle(oracleEOA);

        // Old oracle signature should now be invalid since oracle was revoked
        vm.expectRevert(JJSKIN.InvalidOracleAttestation.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);

        // Restore oracle for other tests
        vm.prank(owner);
        marketplace.registerOracle(abi.encode(oracleEOA));
    }

    function test_Settlement_RejectsWhenNoPurchaseExists() public {
        // submitSettlement checks purchase exists before verifying oracle signature
        uint64 rawAssetId = 999;
        bytes memory dummySig = new bytes(65);

        vm.expectRevert(JJSKIN.NoPurchaseExists.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, dummySig);
    }

    function test_Settlement_RejectsUnregisteredOracle() public {
        // Create a purchase so we get past the NoPurchaseExists check
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(999);
        _createListingAndPurchase(assetId, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, 111);

        // Sign with a key that's not a registered oracle
        uint256 fakeOracleKey = 0xBAD;
        uint64 raw = 999;
        (,,, uint48 tradeOfferId) = marketplace.purchases(assetId);
        bytes memory sig = _signSettlement(raw, tradeOfferId, 0, 0);

        // Replace with signature from unregistered key
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)"),
            raw, tradeOfferId, uint8(0), uint8(0)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fakeOracleKey, digest);
        bytes memory fakeSig = abi.encodePacked(r, s, v);

        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(raw, 0, 0, fakeSig);
    }

    // ========== Helper Functions ==========

    // EIP-712 type hash for oracle attestation
    bytes32 private constant ITEM_ATTESTATION_TYPEHASH = keccak256(
        "ItemAttestation(uint64 assetId,uint64 itemDetail)"
    );

    uint64 constant MOCK_TRADE_OFFER_ID_SEC = 12345678;

    function _createPurchase() internal returns (JJSKIN.AssetId) {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller))
        });

        bytes memory signature = _getSignature(listing, seller);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);

        // Seller commits trade offer (creates escrow commitment)
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID_SEC);

        return assetId;
    }

    function _createPurchaseAndComplete(address _seller) internal {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(99));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, _seller, "complete"))
        });

        bytes memory signature = _getSignature(listing, _seller);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, _seller, signature);

        // Seller commits trade offer (creates escrow commitment)
        vm.prank(_seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID_SEC + 99);

        // Oracle releases funds directly after verifying trade completion off-chain
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);
    }
}
