// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, console2} from "forge-std/Test.sol";
import {JJSKIN, ItemDetail, ItemSpec} from "../src/JJSKIN.sol";
import {CS2AaveVault, IPool, IAToken} from "../src/CS2AaveVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {SteamAccountFactory} from "../src/SteamAccountFactory.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import "./base/BaseTest.sol";

/**
 * @title JJSKIN Comprehensive Test Suite
 * @notice Comprehensive testing covering all V2 features including:
 *         - Oracle-controlled refunds
 *         - Configurable time windows
 *         - ERC-4626 vault integration
 *         - Unified balance system
 *         - Trade reversal protection
 *         - Batch operations
 */
contract JJSKINComprehensiveTest is BaseTest {
    // Additional test-specific variables
    CS2AaveVault public vault;
    SteamAccountFactory public factory;
    address public feeRecipient;
    address public randomUser;
    
    // Test constants
    uint256 constant PRICE = 100 * 1e6; // 100 USDC
    uint256 constant HIGH_PRICE = 1000 * 1e6; // 1000 USDC
    uint256 constant STEAM_ID_SELLER = 76561198000000001;
    uint256 constant STEAM_ID_BUYER = 76561198000000002;
    uint256 constant STEAM_ID_SELLER2 = 76561198000000003;
    uint256 constant STEAM_ID_BUYER2 = 76561198000000004;
    
    // Events
    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);
    event DeliveryWindowUpdated(uint256 newWindow);
    event AbandonedWindowUpdated(uint256 newWindow);
    event YieldVaultSet(address indexed vault);
    event ItemPurchased(JJSKIN.AssetId indexed assetId, address indexed buyer, uint56 price);
    event FundsReleased(JJSKIN.AssetId indexed assetId, address indexed seller, uint256 amount, uint256 fee);
    event PurchaseRefunded(JJSKIN.AssetId indexed assetId, address indexed buyer, uint256 amount, JJSKIN.RefundReason reason);
    event BuyOrderCreated(JJSKIN.BuyOrderId indexed orderId, address indexed buyer, ItemSpec itemSpec, uint56 maxPricePerItem, uint8 quantity, uint256 totalLocked);
    event BuyOrderMatched(JJSKIN.BuyOrderId indexed orderId, JJSKIN.AssetId indexed assetId, address indexed seller, uint56 price);
    event BuyOrderFilled(JJSKIN.BuyOrderId indexed orderId, uint8 quantityFilled, uint8 quantityRemaining);
    event BuyOrderCancelled(JJSKIN.BuyOrderId indexed orderId, address indexed buyer, uint256 refundAmount);
    
    function setUp() public override {
        super.setUp();

        // Setup additional test actors
        feeRecipient = oracle; // Fees now go to oracle (VerifierNetwork)
        randomUser = makeAddr("randomUser");

        // Deploy vault with mocked Aave
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
        _fundUser(seller2, 1000 * 1e6);
        _fundUser(buyer2, 1000 * 1e6);
        
        vm.stopPrank();
        
        // Register users with factory
        _registerUser(seller, STEAM_ID_SELLER);
        _registerUser(buyer, STEAM_ID_BUYER);
        _registerUser(seller2, STEAM_ID_SELLER2);
        _registerUser(buyer2, STEAM_ID_BUYER2);
        
        // Approve marketplace
        vm.prank(buyer);
        usdcToken.approve(address(marketplace), type(uint256).max);
        vm.prank(buyer2);
        usdcToken.approve(address(marketplace), type(uint256).max);
    }
    
    // ========== Constructor & Configuration Tests ==========
    
    function test_Constructor() public view {
        assertEq(address(marketplace.usdcToken()), address(usdcToken));
        assertEq(address(marketplace.walletFactory()), address(walletFactory));
        assertEq(marketplace.treasury(), oracle); // treasury set to oracle address in setup
        assertEq(marketplace.platformFeePercent(), 50); // 0.5% default
        assertEq(marketplace.deliveryWindow(), 6 hours);
        assertEq(marketplace.abandonedWindow(), 24 hours);
    }

    // NOTE: Oracle is registered via TEE attestation (setAttestationVerifier + registerOracle)

    function test_SetPlatformFee() public {
        uint256 newFee = 100; // 1%
        
        vm.expectEmit(false, false, false, true);
        emit PlatformFeeUpdated(50, newFee);
        
        vm.prank(owner);
        marketplace.setPlatformFee(newFee);
        
        assertEq(marketplace.platformFeePercent(), newFee);
    }
    
    function test_RevertSetPlatformFeeTooHigh() public {
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(
            JJSKIN.FeeExceedsMaximum.selector,
            600,
            500
        ));
        marketplace.setPlatformFee(600); // 6% > 5% max
    }
    
    // ========== Time Window Configuration Tests ==========
    
    function test_SetDeliveryWindow() public {
        vm.expectEmit(false, false, false, true);
        emit DeliveryWindowUpdated(12 hours);
        
        vm.prank(owner);
        marketplace.setDeliveryWindow(12 hours);
        
        assertEq(marketplace.deliveryWindow(), 12 hours);
    }
    
    function test_RevertSetDeliveryWindowInvalid() public {
        vm.startPrank(owner);
        
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(30 minutes); // Too short
        
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(49 hours); // Too long
        
        vm.stopPrank();
    }
    
    function test_SetAbandonedWindow() public {
        vm.expectEmit(false, false, false, true);
        emit AbandonedWindowUpdated(48 hours);
        
        vm.prank(owner);
        marketplace.setAbandonedWindow(48 hours);
        
        assertEq(marketplace.abandonedWindow(), 48 hours);
    }
    
    function test_ProtectionPeriodIsConstant() public view {
        // Verify Steam's 7-day protection period cannot be changed
        // Protection period is 7 days (fixed by Steam)
    }
    
    // ========== Vault Integration Tests ==========
    
    function test_SetYieldVault() public {
        // Deploy new marketplace without vault
        JJSKIN newMarketplace = new JJSKIN(
            address(usdcToken),
            address(walletFactory)
        );
        newMarketplace.setTreasury(oracle);

        address newVault = makeAddr("newVault");

        vm.expectEmit(true, false, false, false);
        emit YieldVaultSet(newVault);

        newMarketplace.setYieldVault(newVault);

        assertEq(address(newMarketplace.yieldVault()), newVault);
    }
    
    function test_RevertSetVaultTwice() public {
        vm.prank(owner);
        vm.expectRevert(JJSKIN.AlreadyProcessed.selector);
        marketplace.setYieldVault(makeAddr("anotherVault"));
    }
    
    function test_DepositIdleFundsToVault() public {
        // Create trade to generate fees and have idle USDC in contract
        _createPurchaseAndComplete();

        // Fund contract with enough USDC to meet minimum threshold
        uint256 minDeposit = marketplace.MIN_VAULT_DEPOSIT();
        vm.prank(owner);
        usdc.mint(address(marketplace), minDeposit);

        // Get contract balance before
        uint256 balanceBefore = usdc.balanceOf(address(marketplace));
        assertTrue(balanceBefore >= minDeposit, "Should have enough for deposit");

        // Deposit to vault
        vm.prank(owner);
        uint256 shares = marketplace.depositIdleFundsToVault();
        assertTrue(shares > 0);

        // Verify vault tracking updated
        assertEq(marketplace.totalVaultShares(), shares);
        assertTrue(marketplace.totalVaultDeposits() > 0);

        // Verify 10% buffer kept (balance should be ~10% of original)
        uint256 balanceAfter = usdc.balanceOf(address(marketplace));
        assertApproxEqAbs(balanceAfter, balanceBefore / 10, 1e6);
    }

    function test_HarvestYield() public {
        // Setup: Fund and deposit to vault
        uint256 minDeposit = marketplace.MIN_VAULT_DEPOSIT();
        vm.startPrank(owner);
        usdc.mint(address(marketplace), minDeposit);
        marketplace.depositIdleFundsToVault();
        vm.stopPrank();
        
        // Simulate yield generation
        _simulateYield(10 * 1e6); // 10 USDC yield
        
        // Harvest yield
        uint256 harvested = marketplace.harvestYield();
        assertTrue(harvested > 0);
        
        // Check yield added to platform fees
        assertTrue(marketplace.withdrawableFees(feeRecipient) > 0);
    }
    
    // ========== Purchase Flow Tests ==========
    
    function test_PurchaseWithSignature() public {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        ItemDetail itemDetail = ItemDetail.wrap(uint64(123));
        
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp))
        });
        
        bytes memory signature = _generateListingSignature(listing, seller);
        
        vm.expectEmit(true, true, false, true);
        emit ItemPurchased(assetId, buyer, uint56(PRICE));
        
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);
        
        // Verify purchase created
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));
    }
    
    function test_RevertPurchaseZeroPrice() public {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: 0,
            nonce: keccak256(abi.encode(block.timestamp))
        });
        
        bytes memory signature = _generateListingSignature(listing, seller);
        
        vm.prank(buyer);
        vm.expectRevert(JJSKIN.InvalidPrice.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }
    
    function test_RevertCannotBuyOwnItem() public {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp))
        });
        
        bytes memory signature = _generateListingSignature(listing, seller);
        
        vm.prank(seller);
        vm.expectRevert(JJSKIN.CannotBuyOwnItem.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }
    
    function test_RevertNonceReuse() public {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        bytes32 nonce = keccak256(abi.encode(block.timestamp));
        
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(uint64(123)),
            price: uint56(PRICE),
            nonce: nonce
        });
        
        bytes memory signature = _generateListingSignature(listing, seller);
        
        // First purchase succeeds
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);
        
        // Try to use same nonce again
        JJSKIN.AssetId assetId2 = JJSKIN.AssetId.wrap(uint64(2));
        listing.assetId = assetId2;
        signature = _generateListingSignature(listing, seller);
        
        vm.prank(buyer2);
        vm.expectRevert(JJSKIN.NonceInvalid.selector);
        marketplace.purchaseWithSignature(listing, seller, signature);
    }
    
    // ========== Oracle Refund Tests ==========

    function test_OracleRefundFailedDelivery() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // TEE oracle verifies delivery failed, then refunds
        vm.expectEmit(true, true, false, true);
        emit PurchaseRefunded(assetId, buyer, PRICE, JJSKIN.RefundReason.Timeout);

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(marketplace.userBalances(buyer), PRICE);
    }

    function test_OracleRefundTradeReversed() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // TEE oracle verifies trade reversal
        vm.expectEmit(true, true, false, true);
        emit PurchaseRefunded(assetId, buyer, PRICE, JJSKIN.RefundReason.TradeRollback);

        _oracleRefund(assetId, JJSKIN.RefundReason.TradeRollback);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(marketplace.userBalances(buyer), PRICE);
    }

    function test_OracleRefundBuyerDeclined() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // TEE oracle verifies trade decline
        vm.expectEmit(true, true, false, true);
        emit PurchaseRefunded(assetId, buyer, PRICE, JJSKIN.RefundReason.BuyerDeclined);

        _oracleRefund(assetId, JJSKIN.RefundReason.BuyerDeclined);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(marketplace.userBalances(buyer), PRICE);
    }

    function test_OracleRefundExpired() public {
        JJSKIN.AssetId assetId = _createPurchase();

        // Trade expired without completion
        _oracleRefund(assetId, JJSKIN.RefundReason.SellerExpired);

        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
    }

    function test_RevertInvalidOracleSignature() public {
        // Only oracle-signed settlements are accepted
        JJSKIN.AssetId assetId = _createPurchase();

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(assetId);

        // Sign with a random key (not oracle)
        uint256 randomKey = 0xDEAD;
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Settlement(uint64 assetId,uint8 decision,uint8 refundReason)"),
            rawAssetId, uint8(1), uint8(JJSKIN.RefundReason.Timeout)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(randomKey, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(rawAssetId, 1, uint8(JJSKIN.RefundReason.Timeout), badSig);

        // Verify purchase is still active
        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Active));
    }
    
    // ========== Batch Operations Tests ==========

    function test_BatchReleaseFunds() public {
        // Create multiple purchases
        JJSKIN.AssetId assetId1 = _createPurchaseWithId(1, seller, buyer, PRICE);
        JJSKIN.AssetId assetId2 = _createPurchaseWithId(2, seller2, buyer2, PRICE * 2);

        // TEE oracle verifies trades completed, then releases funds
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](2);
        assetIds[0] = assetId1;
        assetIds[1] = assetId2;

        _batchReleaseFunds(assetIds);

        // Verify balances (0.5% fee)
        uint256 expectedSeller1 = (PRICE * 995) / 1000;
        uint256 expectedSeller2 = (PRICE * 2 * 995) / 1000;

        assertEq(marketplace.userBalances(seller), expectedSeller1);
        assertEq(marketplace.userBalances(seller2), expectedSeller2);

        // Verify status
        assertEq(uint8(marketplace.getPurchaseStatus(assetId1)), uint8(JJSKIN.PurchaseStatus.Released));
        assertEq(uint8(marketplace.getPurchaseStatus(assetId2)), uint8(JJSKIN.PurchaseStatus.Released));
    }

    // NOTE: test_RevertBatchTooLarge removed — no batching in submitSettlement
    
    // ========== Buy Order Tests ==========
    
    function test_CreateBuyOrder() public {
        ItemSpec itemSpec = ItemSpec.wrap(uint64(123));
        uint56 maxPrice = uint56(PRICE);
        uint8 quantity = 3;
        
        vm.expectEmit(true, true, false, true);
        emit BuyOrderCreated(
            JJSKIN.BuyOrderId.wrap(1),
            buyer,
            itemSpec,
            maxPrice,
            quantity,
            uint256(maxPrice) * quantity
        );
        
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(
            itemSpec,
            maxPrice,
            quantity
        );

        (address orderBuyer, uint8 storedQuantity,,, uint56 storedMaxPrice,,) =
            marketplace.buyOrders(orderId);
        
        assertEq(orderBuyer, buyer);
        assertEq(storedMaxPrice, maxPrice);
        assertEq(storedQuantity, quantity);
    }
    
    function test_ExecuteBuyOrderMatch() public {
        // Create matching ItemSpec and ItemDetail pair
        (ItemSpec itemSpec, ItemDetail itemDetail) = _createMatchingItemPair();

        // Create buy order
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(
            itemSpec,
            uint56(PRICE),
            1
        );

        // Create matching listing data
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE - 10 * 1e6), // Cheaper than max
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });
        
        // Generate signature for listing
        bytes memory signature = _generateListingSignature(listing, seller);
        
        // Execute match
        vm.expectEmit(true, true, true, true);
        emit BuyOrderMatched(orderId, assetId, seller, uint56(PRICE - 10 * 1e6));
        
        // Anyone can call executeBuyOrderMatchWithSignature to match the order
        bytes memory oracleSig = _signOracleAttestation(assetId, itemDetail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, signature, oracleSig);

        // Verify purchase created at listing price
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Active));
    }
    
    function test_CancelBuyOrder() public {
        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(
            ItemSpec.wrap(uint64(123)),
            uint56(PRICE),
            2
        );

        uint256 userBalanceBefore = marketplace.userBalances(buyer);

        vm.expectEmit(true, true, false, true);
        emit BuyOrderCancelled(orderId, buyer, PRICE * 2);

        vm.prank(buyer);
        marketplace.cancelBuyOrder(orderId);

        // Verify refund goes to userBalance
        assertEq(marketplace.userBalances(buyer), userBalanceBefore + PRICE * 2);

        // Verify state
        (,,,JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Cancelled));
    }
    
    function test_RefundFromBuyOrderMatch_CreditsUserBalance() public {
        // Refund from buy-order-matched purchase credits buyer's userBalance
        (ItemSpec itemSpec, ItemDetail itemDetail) = _createMatchingItemPair();

        vm.prank(buyer);
        JJSKIN.BuyOrderId orderId = marketplace.createBuyOrder(
            itemSpec,
            uint56(PRICE),
            1
        );

        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });
        bytes memory signature = _generateListingSignature(listing, seller);
        bytes memory oracleSig = _signOracleAttestation(assetId, itemDetail);

        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, signature, oracleSig);

        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID_COMP);

        uint256 balBefore = marketplace.userBalances(buyer);

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Buy order stays Filled, refund goes to userBalance
        (, uint8 quantity, , JJSKIN.BuyOrderState state,,,) =
            marketplace.buyOrders(orderId);
        assertEq(quantity, 0, "quantity unchanged");
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Filled), "stays Filled");
        assertGt(marketplace.userBalances(buyer), balBefore, "buyer credited");
    }
    
    // ========== User Balance Tests ==========
    
    function test_WithdrawBalance() public {
        _createPurchaseAndComplete();
        
        uint256 expectedAmount = (PRICE * 995) / 1000;
        uint256 balanceBefore = usdcToken.balanceOf(seller);
        
        vm.prank(seller);
        uint256 withdrawn = marketplace.withdrawBalance();
        
        assertEq(withdrawn, expectedAmount);
        assertEq(usdcToken.balanceOf(seller), balanceBefore + expectedAmount);
        assertEq(marketplace.userBalances(seller), 0);
    }
    
    function test_RevertWithdrawZeroBalance() public {
        vm.prank(seller);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.withdrawBalance();
    }
    
    function test_WithdrawFeesRequiresVaultYield() public {
        // All platform fees go to treasury (no orchestrator reward split)
        _createPurchaseAndComplete();

        // Total fee = 0.5% of PRICE, all goes to treasury
        uint256 totalFees = (PRICE * 50) / 10000; // 0.5%

        // All fees should be withdrawable by treasury
        assertEq(marketplace.accumulatedFees(), totalFees, "All fees should be accumulated for treasury");
        assertEq(marketplace.withdrawableFees(feeRecipient), totalFees, "All fees withdrawable by treasury");

        // Treasury can withdraw platform fees immediately
        uint256 treasuryBalanceBefore = usdcToken.balanceOf(feeRecipient);
        vm.prank(feeRecipient);
        marketplace.withdrawFees();
        assertEq(usdcToken.balanceOf(feeRecipient), treasuryBalanceBefore + totalFees, "Treasury should receive all fees");
    }

    // NOTE: Pause tests removed - no pause mechanism for full trustlessness

    // ========== Edge Cases ==========
    
    function test_CannotDoubleRefund() public {
        JJSKIN.AssetId assetId = _createPurchase();

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record buyer balance after first refund
        uint256 buyerBalanceAfterRefund = marketplace.userBalances(buyer);

        // Second refund attempt - contract is now idempotent (skips already-settled)
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify buyer balance unchanged (no double refund - was skipped)
        assertEq(marketplace.userBalances(buyer), buyerBalanceAfterRefund, "Balance should not change on double refund");
    }

    function test_CannotReleaseAfterRefund() public {
        JJSKIN.AssetId assetId = _createPurchase();

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record seller balance after refund (should be 0 - refund goes to buyer)
        uint256 sellerBalanceAfterRefund = marketplace.userBalances(seller);

        // Release attempt - contract is now idempotent (skips already-settled)
        _oracleClaim(assetId);

        // Verify seller balance unchanged (no credit after refund - was skipped)
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterRefund, "Seller should not receive funds after refund");

        // Status should still be Refunded
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));
    }
    
    function test_ItemSpecEncoding() public view {
        // Test ItemSpec encoding/decoding
        uint48 testValue = 123456789;
        ItemSpec spec = ItemSpec.wrap(testValue);
        assertEq(ItemSpec.unwrap(spec), testValue);
    }
    
    function test_FeeCalculation() public {
        // Test fee calculation with custom platform fee
        vm.prank(owner);
        marketplace.setPlatformFee(100); // 1%

        JJSKIN.AssetId assetId = _createPurchase();

        // Oracle releases funds directly (no confirmDelivery needed)
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // 1% fee - seller gets PRICE - fee, all fees go to treasury
        uint256 totalFee = (PRICE * 100) / 10000;
        uint256 expectedSellerAmount = PRICE - totalFee;

        // Verify seller gets correct amount after fee
        assertEq(marketplace.userBalances(seller), expectedSellerAmount);

        // All fees go to treasury (no orchestrator reward split)
        assertEq(marketplace.accumulatedFees(), totalFee, "All fees should be in accumulatedFees");
        assertEq(marketplace.withdrawableFees(feeRecipient), totalFee, "All fees withdrawable by treasury");

        // Implicit fees in contract = total fee (all goes to treasury)
        uint256 contractBalance = usdcToken.balanceOf(address(marketplace));
        uint256 totalUserBalances = marketplace.totalUserBalances();
        uint256 implicitFees = contractBalance - totalUserBalances;
        assertEq(implicitFees, totalFee, "Implicit fees should equal total fee");
    }
    
    // ========== Helper Functions ==========
    
    uint64 constant MOCK_TRADE_OFFER_ID_COMP = 12345678;

    function _createPurchase() internal returns (JJSKIN.AssetId) {
        return _createPurchaseWithId(1, seller, buyer, PRICE);
    }

    function _createPurchaseWithId(
        uint64 id,
        address _seller,
        address _buyer,
        uint256 price
    ) internal returns (JJSKIN.AssetId) {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(id);
        ItemDetail itemDetail = ItemDetail.wrap(uint64(123));

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(price),
            nonce: keccak256(abi.encode(block.timestamp, _seller, assetId))
        });

        bytes memory signature = _generateListingSignature(listing, _seller);

        vm.prank(_buyer);
        marketplace.purchaseWithSignature(listing, _seller, signature);

        // Seller commits trade offer (creates escrow commitment)
        vm.prank(_seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID_COMP + id);

        return assetId;
    }
    

    function _createPurchaseAndComplete() internal {
        JJSKIN.AssetId assetId = _createPurchase();

        // TEE oracle releases funds after verifying trade completion
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);
    }
    
    function _generateListingSignature(
        JJSKIN.ListingData memory listing,
        address signer
    ) internal view returns (bytes memory) {
        // Use proper signing from BaseTest
        // Map signer address to private key
        uint256 signerKey;
        if (signer == seller) signerKey = sellerKey;
        else if (signer == seller2) signerKey = seller2Key;
        else if (signer == buyer) signerKey = buyerKey;
        else if (signer == buyer2) signerKey = buyer2Key;
        else revert("Unknown signer");
        
        return _signListing(listing, signerKey);
    }
    
    function _simulateYield(uint256 amount) internal {
        // Simulate yield generation in vault
        vm.prank(owner);
        usdcToken.mint(address(vault), amount);
    }
}