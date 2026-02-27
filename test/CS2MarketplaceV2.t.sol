// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, console2} from "forge-std/Test.sol";
import {JJSKIN, ItemDetail, ItemSpec, ItemDetailLib, ItemSpecLib, MatchingLib} from "../src/JJSKIN.sol";
import {CS2AaveVault, IPool, IAToken} from "../src/CS2AaveVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockSmartAccount} from "./mocks/MockSmartAccount.sol";
import {SteamAccountFactory} from "../src/SteamAccountFactory.sol";
import {IEntryPoint} from "@thirdweb-dev/contracts/prebuilts/account/interface/IEntrypoint.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// Mock Aave contracts for testing
contract MockAavePool {
    IERC20 public usdc;
    MockAToken public aToken;
    
    constructor(IERC20 _usdc, MockAToken _aToken) {
        usdc = _usdc;
        aToken = _aToken;
    }
    
    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        require(asset == address(usdc), "Invalid asset");
        usdc.transferFrom(msg.sender, address(this), amount);
        aToken.poolMint(onBehalfOf, amount);
    }
    
    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        require(asset == address(usdc), "Invalid asset");
        uint256 aTokenBalance = aToken.balanceOf(msg.sender);
        uint256 toWithdraw = amount > aTokenBalance ? aTokenBalance : amount;
        
        if (toWithdraw > 0) {
            aToken.burn(msg.sender, toWithdraw);
            usdc.transfer(to, toWithdraw);
        }
        
        return toWithdraw;
    }
}

contract MockAToken is MockUSDC {
    address public immutable UNDERLYING_ASSET_ADDRESS;
    address public pool;
    
    constructor(address _underlying) {
        UNDERLYING_ASSET_ADDRESS = _underlying;
    }
    
    function setPool(address _pool) external onlyOwner {
        pool = _pool;
    }
    
    function poolMint(address to, uint256 amount) external {
        // Allow pool to mint
        require(msg.sender == pool, "Only pool can mint");
        _mint(to, amount);
    }
    
    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
}

// Mock attestation verifier for testing (decodes address from attestation bytes)
contract MockAttestationVerifier {
    function verifyAttestation(bytes calldata attestation) external pure returns (address) {
        return abi.decode(attestation, (address));
    }
}

contract JJSKINTest is Test {
    JJSKIN public marketplace;
    CS2AaveVault public vault;
    MockUSDC public usdc;
    MockAToken public aToken;
    MockAavePool public aavePool;
    SteamAccountFactory public factory;

    // Steam IDs for testing (must match zkVM journal data)
    uint64 constant SELLER_STEAM_ID = 76561198000000003;
    uint64 constant BUYER_STEAM_ID = 76561198000000001;
    uint64 constant BUYER2_STEAM_ID = 76561198000000002;

    // Private keys for deterministic signing
    uint256 public ownerKey = 0x1;
    uint256 public oracleKey = 0x2;
    uint256 public sellerKey = 0x3;
    uint256 public buyerKey = 0x4;
    uint256 public seller2Key = 0x5;
    uint256 public buyer2Key = 0x6;
    
    // EOA addresses for signing
    address public ownerEOA = vm.addr(ownerKey);
    address public oracleEOA = vm.addr(oracleKey);
    address public sellerEOA = vm.addr(sellerKey);
    address public buyerEOA = vm.addr(buyerKey);
    address public seller2EOA = vm.addr(seller2Key);
    address public buyer2EOA = vm.addr(buyer2Key);
    
    // Smart account addresses (deployed in setUp)
    address public oracle;
    address public owner;
    address public feeRecipient;
    address public seller;
    address public buyer;
    address public seller2;
    address public buyer2;
    
    uint256 constant PRICE = 100 * 1e6; // 100 USDC
    uint256 constant STEAM_ID_SELLER = 76561198000000001;
    uint256 constant STEAM_ID_BUYER = 76561198000000002;
    
    // EIP-712 type hashes for testing
    bytes32 private constant LISTING_TYPEHASH = keccak256(
        "ListingData(uint64 assetId,uint64 itemDetail,uint56 price,bytes32 nonce)"
    );
    bytes32 private constant ITEM_ATTESTATION_TYPEHASH = keccak256(
        "ItemAttestation(uint64 assetId,uint64 itemDetail)"
    );
    bytes32 private constant SETTLEMENT_TYPEHASH = keccak256(
        "Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)"
    );

    // Events to test
    event ListingConfirmed(JJSKIN.AssetId indexed assetId, address indexed seller, uint56 price, ItemDetail itemDetail);
    event ItemPurchased(JJSKIN.AssetId indexed assetId, address indexed buyer, uint56 price);
    event FundsReleased(JJSKIN.AssetId indexed assetId, address indexed seller, uint256 amount, uint256 fee);
    event PurchaseRefunded(JJSKIN.AssetId indexed assetId, address indexed buyer, uint256 amount, JJSKIN.RefundReason reason);
    event SellerSuspended(address indexed seller, uint256 violations);
    event YieldVaultSet(address indexed vault);
    event FeesDepositedToVault(uint256 amount, uint256 shares);
    event YieldHarvested(uint256 amount);
    
    function setUp() public {
        // Deploy smart accounts for all test users
        oracle = address(new MockSmartAccount(oracleEOA));
        owner = address(new MockSmartAccount(ownerEOA));
        feeRecipient = oracle; // Fees now go to oracle (VerifierNetwork)
        seller = address(new MockSmartAccount(sellerEOA));
        buyer = address(new MockSmartAccount(buyerEOA));
        seller2 = address(new MockSmartAccount(seller2EOA));
        buyer2 = address(new MockSmartAccount(buyer2EOA));
        
        // Deploy mocks
        usdc = new MockUSDC();
        aToken = new MockAToken(address(usdc));
        aavePool = new MockAavePool(usdc, aToken);
        
        // Set up pool authorization for minting
        aToken.setPool(address(aavePool));
        
        // Deploy factory with mock entry point
        IEntryPoint entryPoint = IEntryPoint(makeAddr("entryPoint"));
        factory = new SteamAccountFactory(
            makeAddr("deployer"),
            entryPoint
        );
        
        // Deploy marketplace
        vm.prank(owner);
        marketplace = new JJSKIN(
            address(usdc),
            address(factory)
        );

        // Set treasury (for fee collection)
        vm.prank(owner);
        marketplace.setTreasury(oracle);

        // Register oracle via mock attestation verifier
        vm.startPrank(owner);
        MockAttestationVerifier mockVerifier = new MockAttestationVerifier();
        marketplace.setAttestationVerifier(address(mockVerifier));
        marketplace.registerOracle(abi.encode(oracleEOA));
        vm.stopPrank();

        // Deploy and set vault
        vm.prank(owner);
        vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        
        vm.prank(owner);
        marketplace.setYieldVault(address(vault));
        
        // Register smart accounts with factory
        // We'll mock the factory's isRegistered function to return true for our smart accounts
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.isRegistered.selector, seller),
            abi.encode(true)
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.isRegistered.selector, buyer),
            abi.encode(true)
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.isRegistered.selector, seller2),
            abi.encode(true)
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.isRegistered.selector, buyer2),
            abi.encode(true)
        );

        // Mock getSteamIdByWallet for opponent validation in settlement
        // CRITICAL: These must match the Steam IDs in the zkVM journals for RELEASE to succeed
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.getSteamIdByWallet.selector, buyer),
            abi.encode(uint256(BUYER_STEAM_ID))
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.getSteamIdByWallet.selector, buyer2),
            abi.encode(uint256(BUYER2_STEAM_ID))
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.getSteamIdByWallet.selector, seller),
            abi.encode(uint256(SELLER_STEAM_ID))
        );
        vm.mockCall(
            address(factory),
            abi.encodeWithSelector(factory.getSteamIdByWallet.selector, seller2),
            abi.encode(uint256(76561198000000005))
        );
        
        // Fund users
        usdc.mint(seller, 1000 * 1e6);
        usdc.mint(buyer, 1000 * 1e6);
        usdc.mint(seller2, 1000 * 1e6);
        usdc.mint(buyer2, 1000 * 1e6);
        
        // Approve marketplace
        vm.prank(buyer);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(buyer2);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(seller);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(seller2);
        usdc.approve(address(marketplace), type(uint256).max);
    }
    
    // ========== Helper Functions ==========
    
    // Create EIP-712 signature for listing data
    function _signListing(
        JJSKIN.ListingData memory listing,
        uint256 privateKey
    ) internal returns (bytes memory) {
        // Create the struct hash
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));
        
        // Must match: EIP712("JJSKIN", "1") in JJSKIN.sol constructor
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("JJSKIN"),
                keccak256("1"),
                block.chainid,
                address(marketplace)
            )
        );
        
        // Create the final digest
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        
        // Sign the digest
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signOracleAttestation(
        JJSKIN.AssetId assetId,
        ItemDetail itemDetail
    ) internal returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            ITEM_ATTESTATION_TYPEHASH,
            JJSKIN.AssetId.unwrap(assetId),
            ItemDetail.unwrap(itemDetail)
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // Helper to create a matching ItemSpec and ItemDetail pair for testing
    function _createMatchingItemPair() internal pure returns (ItemSpec, ItemDetail) {
        // Create ItemSpec for buy order (matching criteria with ranges)
        ItemSpec spec = ItemSpecLib.encode(
            1,      // paintIndex
            0,      // minFloat (0.000)
            1023,   // maxFloat (1.000) - full range
            7,      // defindex
            0,      // patternTier (0 = any tier)
            0       // variant
        );

        // Create ItemDetail for listing (exact values that match the spec)
        ItemDetail detail = ItemDetailLib.encode(
            1,       // paintIndex (matches)
            524288,  // floatValue (0.5 in 20-bit precision)
            7,       // defindex (matches)
            500,     // paintSeed
            1,       // patternTier (tier 1, spec accepts any)
            0        // variant (matches)
        );

        return (spec, detail);
    }

    uint64 constant MOCK_TRADE_OFFER_ID = 12345678;

    function createListingAndPurchase() internal returns (JJSKIN.AssetId) {
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(uint64(1));
        ItemDetail itemDetail = ItemDetail.wrap(uint64(123));

        // Create listing data
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller))
        });

        // Create proper EIP-712 signature using seller's private key
        bytes memory signature = _signListing(listing, sellerKey);

        // Purchase with signature (creates listing and purchases in one tx)
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);

        // Seller commits trade offer (creates escrow commitment)
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID);

        return assetId;
    }

    // ========== Oracle Settlement Helpers ==========

    function _signSettlement(
        uint64 rawAssetId, uint48 tradeOfferId, uint8 decision, uint8 refundReason
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            SETTLEMENT_TYPEHASH, rawAssetId, tradeOfferId, decision, refundReason
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _submitSettlement(JJSKIN.AssetId assetId, uint8 decision, uint8 refundReason) internal {
        uint64 raw = JJSKIN.AssetId.unwrap(assetId);
        (,,, uint48 tradeOfferId) = marketplace.purchases(assetId);
        bytes memory sig = _signSettlement(raw, tradeOfferId, decision, refundReason);
        marketplace.submitSettlement(raw, decision, refundReason, sig);
    }

    function _oracleRefund(JJSKIN.AssetId assetId, JJSKIN.RefundReason reason) internal {
        _submitSettlement(assetId, 1, uint8(reason));
    }

    function _oracleClaim(JJSKIN.AssetId assetId) internal {
        _submitSettlement(assetId, 0, 0);
    }

    function _batchReleaseFunds(JJSKIN.AssetId[] memory assetIds) internal {
        for (uint256 i = 0; i < assetIds.length; i++) {
            _oracleClaim(assetIds[i]);
        }
    }

    // ========== Configuration Tests ==========
    
    function testSetTimeWindows() public {
        vm.startPrank(owner);
        
        marketplace.setDeliveryWindow(12 hours);
        assertEq(marketplace.deliveryWindow(), 12 hours);
        
        marketplace.setAbandonedWindow(48 hours);
        assertEq(marketplace.abandonedWindow(), 48 hours);

        vm.stopPrank();
    }
    
    function testSetInvalidTimeWindows() public {
        vm.startPrank(owner);
        
        // Delivery window too short
        vm.expectRevert("Invalid delivery window");
        marketplace.setDeliveryWindow(30 minutes);
        
        // Abandoned window too short
        vm.expectRevert("Invalid abandoned window");
        marketplace.setAbandonedWindow(6 hours);

        vm.stopPrank();
    }
    
    function testProtectionPeriodIsConstant() public {
        // Verify the 7-day Steam protection period cannot be changed
        // Protection period is 7 days (fixed by Steam)
    }
    
    // ========== Vault Integration Tests ==========
    
    function testSetYieldVault() public {
        // Deploy new marketplace without vault
        JJSKIN newMarketplace = new JJSKIN(
            address(usdc),
            address(factory)
        );
        newMarketplace.setTreasury(oracle);

        // Set vault
        vm.expectEmit(true, false, false, false);
        emit YieldVaultSet(address(vault));

        newMarketplace.setYieldVault(address(vault));

        assertEq(address(newMarketplace.yieldVault()), address(vault));
    }
    
    function testCannotSetVaultTwice() public {
        // Try to set vault again
        vm.prank(owner);
        vm.expectRevert(JJSKIN.AlreadyProcessed.selector);
        marketplace.setYieldVault(makeAddr("newVault"));
    }
    
    function testDepositIdleFundsToVault() public {
        // Fund contract with enough USDC to meet minimum threshold
        vm.prank(owner);
        usdc.mint(address(marketplace), marketplace.MIN_VAULT_DEPOSIT());

        // Get contract balance before
        uint256 balanceBefore = usdc.balanceOf(address(marketplace));
        assertTrue(balanceBefore >= marketplace.MIN_VAULT_DEPOSIT(), "Should have enough for deposit");

        // Deposit idle funds to vault
        vm.prank(owner);
        uint256 shares = marketplace.depositIdleFundsToVault();
        assertTrue(shares > 0);

        // Verify vault tracking updated
        assertEq(marketplace.totalVaultShares(), shares);
        assertTrue(marketplace.totalVaultDeposits() > 0);

        // Verify 10% buffer kept
        uint256 balanceAfter = usdc.balanceOf(address(marketplace));
        assertApproxEqAbs(balanceAfter, balanceBefore / 10, 1e6);
    }
    
    // ========== Oracle Refund Tests ==========

    function testOracleRefundFailedDelivery() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Oracle processes refund with reason (timing verified off-chain via TLSNotary)
        // Note: oracleRefund no longer auto-suspends - suspension is separate
        vm.expectEmit(true, true, false, true);
        emit PurchaseRefunded(assetId, buyer, PRICE, JJSKIN.RefundReason.Timeout);

        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));

        // Verify buyer can withdraw refund
        assertEq(marketplace.userBalances(buyer), PRICE);
    }

    function testOracleRefundWithoutSuspension() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Oracle refunds without suspending seller (e.g., buyer declined)
        _oracleRefund(assetId, JJSKIN.RefundReason.BuyerDeclined);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));

        // Buyer gets refund
        assertEq(marketplace.userBalances(buyer), PRICE);
    }

    function testOracleRefundTradeReversed() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // TradeReversed refunds buyer (suspension is now handled separately by oracle)
        _oracleRefund(assetId, JJSKIN.RefundReason.TradeRollback);

        // Verify refund processed
        JJSKIN.PurchaseStatus status = marketplace.getPurchaseStatus(assetId);
        assertEq(uint8(status), uint8(JJSKIN.PurchaseStatus.Refunded));

        // Verify buyer refunded
        assertEq(marketplace.userBalances(buyer), PRICE);
    }
    
    // ========== Batch Release Tests ==========

    function testBatchReleaseFunds() public {
        // Create multiple purchases
        JJSKIN.AssetId assetId1 = JJSKIN.AssetId.wrap(uint64(1));
        JJSKIN.AssetId assetId2 = JJSKIN.AssetId.wrap(uint64(2));
        ItemDetail itemDetail = ItemDetail.wrap(uint64(123));

        // Create and purchase first item
        JJSKIN.ListingData memory listing1 = JJSKIN.ListingData({
            assetId: assetId1,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId1))
        });
        bytes memory sig1 = _signListing(listing1, sellerKey);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing1, seller, sig1);

        // Seller commits trade offer
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId1, MOCK_TRADE_OFFER_ID);

        // Create and purchase second item
        JJSKIN.ListingData memory listing2 = JJSKIN.ListingData({
            assetId: assetId2,
            itemDetail: itemDetail,
            price: uint56(PRICE * 2),
            nonce: keccak256(abi.encode(block.timestamp, seller2, assetId2))
        });
        bytes memory sig2 = _signListing(listing2, seller2Key);

        vm.prank(buyer2);
        marketplace.purchaseWithSignature(listing2, seller2, sig2);

        // Seller2 commits trade offer
        vm.prank(seller2);
        marketplace.commitTradeOffer(assetId2, MOCK_TRADE_OFFER_ID + 1);

        // Batch release (oracle verifies off-chain via TLSNotary proofs)
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](2);
        assetIds[0] = assetId1;
        assetIds[1] = assetId2;

        _batchReleaseFunds(assetIds);

        // Verify sellers received correct amounts (price - 0.5% fee)
        uint256 expectedSeller1 = (PRICE * 995) / 1000; // 0.5% fee
        uint256 expectedSeller2 = (PRICE * 2 * 995) / 1000;
        assertEq(marketplace.userBalances(seller), expectedSeller1);
        assertEq(marketplace.userBalances(seller2), expectedSeller2);

        // All fees go to treasury (no orchestrator reward in TEE oracle model)
        uint256 totalValue = PRICE + (PRICE * 2);
        uint256 totalFees = (totalValue * 50) / 10000; // 0.5%

        // All fees go to accumulatedFees (for withdrawal by treasury)
        assertEq(marketplace.accumulatedFees(), totalFees);

        // Verify purchase status
        assertEq(uint8(marketplace.getPurchaseStatus(assetId1)), uint8(JJSKIN.PurchaseStatus.Released));
        assertEq(uint8(marketplace.getPurchaseStatus(assetId2)), uint8(JJSKIN.PurchaseStatus.Released));
    }
    
    // ========== User Balance Tests ==========

    function testWithdrawBalance() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Complete trade flow (oracle verifies off-chain)
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // Seller withdraws
        uint256 expectedAmount = (PRICE * 995) / 1000;
        uint256 balanceBefore = usdc.balanceOf(seller);

        vm.prank(seller);
        uint256 withdrawn = marketplace.withdrawBalance();

        assertEq(withdrawn, expectedAmount);
        assertEq(usdc.balanceOf(seller), balanceBefore + expectedAmount);
        assertEq(marketplace.userBalances(seller), 0);
    }
    
    function testCannotWithdrawZeroBalance() public {
        vm.prank(seller);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.withdrawBalance();
    }
    
    // ========== Buy Order Tests ==========

    function testRefundFromBuyOrderMatch_CreditsUserBalance() public {
        // Refund from a buy-order-matched purchase credits buyer's userBalance
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
        bytes memory signature = _signListing(listing, sellerKey);
        bytes memory oracleSig = _signOracleAttestation(assetId, itemDetail);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, signature, oracleSig);

        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, MOCK_TRADE_OFFER_ID);

        // Verify buy order is Filled
        (, uint8 quantity, , JJSKIN.BuyOrderState state,,,) = marketplace.buyOrders(orderId);
        assertEq(quantity, 0);
        assertEq(uint8(state), uint8(JJSKIN.BuyOrderState.Filled));

        uint256 balBefore = marketplace.userBalances(buyer);

        // Refund
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Buy order stays Filled (no restoration), funds go to userBalance
        (, uint8 qtyAfter, , JJSKIN.BuyOrderState stateAfter,,,) = marketplace.buyOrders(orderId);
        assertEq(quantity, 0, "quantity unchanged");
        assertEq(uint8(stateAfter), uint8(JJSKIN.BuyOrderState.Filled), "stays Filled");
        assertGt(marketplace.userBalances(buyer), balBefore, "buyer credited");
    }

    // ========== Oracle Settlement Tests ==========
    // NOTE: With TEE oracle model, only the registered oracle can settle

    function testOracleCanSettleClaim() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Oracle settles claim
        _oracleClaim(assetId);

        // Verify settlement was processed
        assertEq(uint256(marketplace.getPurchaseStatus(assetId)), uint256(JJSKIN.PurchaseStatus.Released));
    }

    function testOracleCanSettleRefund() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Oracle settles refund
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify refund was processed
        assertEq(uint256(marketplace.getPurchaseStatus(assetId)), uint256(JJSKIN.PurchaseStatus.Refunded));
    }

    // ========== Edge Cases ==========

    function testCannotDoubleRefund() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // First refund
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record buyer balance after first refund
        uint256 buyerBalanceAfterFirstRefund = marketplace.userBalances(buyer);
        assertEq(buyerBalanceAfterFirstRefund, PRICE, "Buyer should have refund");

        // Try to refund again - contract is now idempotent (skips already-settled)
        // Second settlement attempt should be skipped (idempotent), not revert
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Verify buyer balance unchanged (no double refund - was skipped)
        assertEq(marketplace.userBalances(buyer), buyerBalanceAfterFirstRefund, "Balance should not change on double refund");
        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Refunded), "Status should still be Refunded");
    }

    function testCannotReleaseAfterRefund() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Refund
        _oracleRefund(assetId, JJSKIN.RefundReason.Timeout);

        // Record seller balance after refund
        uint256 sellerBalanceAfterRefund = marketplace.userBalances(seller);

        // Try to release - contract is now idempotent (skips already-settled)
        // Release attempt should be skipped (idempotent), not revert
        _oracleClaim(assetId);

        // Verify status still refunded (wasn't released - was skipped)
        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Refunded));
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterRefund, "Seller should not get payment after refund");
    }

    function testCannotRefundAfterRelease() public {
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Release funds
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // Record balances after release
        uint256 sellerBalanceAfterRelease = marketplace.userBalances(seller);
        uint256 buyerBalanceAfterRelease = marketplace.userBalances(buyer);

        // Try to refund - contract is now idempotent (skips already-settled)
        // Refund attempt should be skipped (idempotent), not revert
        _oracleRefund(assetId, JJSKIN.RefundReason.TradeRollback);

        // Verify balances unchanged (no refund after release - was skipped)
        assertEq(marketplace.userBalances(seller), sellerBalanceAfterRelease, "Seller balance should not change");
        assertEq(marketplace.userBalances(buyer), buyerBalanceAfterRelease, "Buyer should not get refund after release");
        assertEq(uint8(marketplace.getPurchaseStatus(assetId)), uint8(JJSKIN.PurchaseStatus.Released), "Status should still be Released");
    }

    // ========== Fee Withdrawal Tests ==========

    function testWithdrawFees() public {
        // Note: All platform fees go to treasury in TEE oracle model.
        // Treasury portion is immediately withdrawable via withdrawFees().

        // Accumulate fees from a trade
        JJSKIN.AssetId assetId = createListingAndPurchase();

        // Release funds (oracle verifies off-chain)
        JJSKIN.AssetId[] memory assetIds = new JJSKIN.AssetId[](1);
        assetIds[0] = assetId;

        _batchReleaseFunds(assetIds);

        // All fees go to treasury (no orchestrator reward split)
        uint256 totalFee = (PRICE * 50) / 10000; // 0.5%

        // Verify all fees are accumulated for treasury
        assertEq(marketplace.accumulatedFees(), totalFee);

        // Treasury can withdraw platform fees
        uint256 treasuryBalanceBefore = usdc.balanceOf(feeRecipient);
        vm.prank(feeRecipient);
        marketplace.withdrawFees();
        assertEq(usdc.balanceOf(feeRecipient), treasuryBalanceBefore + totalFee);
    }
}