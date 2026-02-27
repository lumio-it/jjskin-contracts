// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import {JJSKIN, ItemDetail, ItemSpec, ItemDetailLib, ItemSpecLib, MatchingLib} from "../../src/JJSKIN.sol";
import "../../src/interfaces/ISteamAccountFactory.sol";
import "../../src/mocks/MockUSDC.sol";
import "../../src/mocks/MockAave.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "../mocks/MockSmartAccount.sol";

// Mock factory for testing
contract MockSteamAccountFactory {
    mapping(address => bool) public isRegistered;
    mapping(address => uint256) public walletToSteamId;
    mapping(uint256 => address) public steamIdToWallet;
    
    function registerForTesting(address wallet, uint256 steamId) external {
        isRegistered[wallet] = true;
        walletToSteamId[wallet] = steamId;
        steamIdToWallet[steamId] = wallet;
    }
    
    function getSteamIdByWallet(address wallet) external view returns (uint256) {
        return walletToSteamId[wallet];
    }
    
    function getWalletBySteamId(uint256 steamId) external view returns (address) {
        return steamIdToWallet[steamId];
    }
}

// Mock attestation verifier for testing (decodes address from attestation bytes)
contract MockAttestationVerifier {
    function verifyAttestation(bytes calldata attestation) external pure returns (address) {
        return abi.decode(attestation, (address));
    }
}

// Base contract with shared setup and helper functions
abstract contract BaseTest is Test {
    JJSKIN public marketplace;
    MockSteamAccountFactory public walletFactory;
    MockUSDC public usdc;
    MockUSDC public usdcToken;
    MockAavePool public aavePool;
    MockAToken public aToken;
    
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
    
    // Test accounts with deterministic private keys
    uint256 public ownerKey = 0x1;
    uint256 public oracleKey = 0x2;
    uint256 public sellerKey = 0x3;
    uint256 public buyerKey = 0x4;
    uint256 public seller2Key = 0x5;
    uint256 public buyer2Key = 0x6;
    uint256 public user1Key = 0x7;
    uint256 public user2Key = 0x8;
    uint256 public attackerKey = 0x9;
    
    // EOA addresses for signing
    address public ownerEOA = vm.addr(ownerKey);
    address public oracleEOA = vm.addr(oracleKey);
    address public sellerEOA = vm.addr(sellerKey);
    address public buyerEOA = vm.addr(buyerKey);
    address public seller2EOA = vm.addr(seller2Key);
    address public buyer2EOA = vm.addr(buyer2Key);
    address public user1EOA = vm.addr(user1Key);
    address public user2EOA = vm.addr(user2Key);
    address public attackerEOA = vm.addr(attackerKey);
    
    // Smart account addresses (will be deployed in setUp)
    address public owner;
    address public oracle;
    address public seller;
    address public buyer;
    address public seller2;
    address public buyer2;
    address public user1;
    address public user2;
    address public attacker;
    
    // Test constants
    uint56 constant ITEM_PRICE = 10_000_000; // 10 USDC
    JJSKIN.AssetId constant ASSET_ID = JJSKIN.AssetId.wrap(12345);
    JJSKIN.AssetId constant ASSET_ID_2 = JJSKIN.AssetId.wrap(67890);
    
    // Steam IDs
    uint64 constant STEAM_ID_1 = 76561198000000001;
    uint64 constant STEAM_ID_2 = 76561198000000002;
    uint64 constant STEAM_ID_3 = 76561198000000003;
    uint64 constant SELLER_STEAM_ID = 76561198000000003;
    uint64 constant BUYER_STEAM_ID = 76561198000000001;
    uint64 constant BUYER2_STEAM_ID = 76561198000000002;
    
    uint256 public constant INITIAL_BALANCE = 1_000_000_000; // 1000 USDC
    
    // Events are inherited from the CS2Marketplace contract
    
    function setUp() public virtual {
        // Deploy smart accounts for all test users
        owner = address(new MockSmartAccount(ownerEOA));
        oracle = address(new MockSmartAccount(oracleEOA));
        seller = address(new MockSmartAccount(sellerEOA));
        buyer = address(new MockSmartAccount(buyerEOA));
        seller2 = address(new MockSmartAccount(seller2EOA));
        buyer2 = address(new MockSmartAccount(buyer2EOA));
        user1 = address(new MockSmartAccount(user1EOA));
        user2 = address(new MockSmartAccount(user2EOA));
        attacker = address(new MockSmartAccount(attackerEOA));
        
        // Deploy contracts
        vm.startPrank(owner);
        usdc = new MockUSDC();
        usdcToken = usdc; // Alias for compatibility
        
        // Deploy Aave mocks
        aToken = new MockAToken(address(usdc));
        aavePool = new MockAavePool(IERC20(address(usdc)), aToken);
        aToken.setPool(address(aavePool)); // Set the pool address so it can mint
        
        walletFactory = new MockSteamAccountFactory();

        marketplace = new JJSKIN(
            address(usdc),
            address(walletFactory)
        );
        marketplace.setTreasury(oracle); // Use oracle address as treasury for backward compatibility

        // Register oracle via mock attestation verifier
        MockAttestationVerifier mockVerifier = new MockAttestationVerifier();
        marketplace.setAttestationVerifier(address(mockVerifier));
        marketplace.registerOracle(abi.encode(oracleEOA));

        // Fund accounts with USDC (still as owner)
        usdc.mint(buyer, INITIAL_BALANCE);
        usdc.mint(buyer2, INITIAL_BALANCE);
        usdc.mint(seller, INITIAL_BALANCE);
        usdc.mint(seller2, INITIAL_BALANCE);
        usdc.mint(user1, INITIAL_BALANCE);
        usdc.mint(user2, INITIAL_BALANCE);
        usdc.mint(attacker, INITIAL_BALANCE);
        
        vm.stopPrank();
        
        // Register test users with factory wallets
        _registerWallet(buyer, 76561198000000001);
        _registerWallet(buyer2, 76561198000000002);
        _registerWallet(seller, 76561198000000003);
        _registerWallet(seller2, 76561198000000005);
        _registerWallet(address(this), 76561198000000004);
        
        // Approve marketplace
        vm.prank(buyer);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(buyer2);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(seller);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(seller2);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(user1);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(user2);
        usdc.approve(address(marketplace), type(uint256).max);
        vm.prank(attacker);
        usdc.approve(address(marketplace), type(uint256).max);
    }
    
    // ========== Helper Functions ==========
    
    // Helper to fund a user with USDC
    function _fundUser(address user, uint256 amount) internal {
        usdc.mint(user, amount);
    }
    
    // Helper to register a user with the factory
    function _registerUser(address user, uint256 steamId) internal {
        walletFactory.registerForTesting(user, steamId);
    }
    
    // Helper to create listing data (off-chain)
    function _createListingData(
        JJSKIN.AssetId assetId,
        address _seller,
        uint56 price
    ) internal view returns (JJSKIN.ListingData memory) {
        return JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: ItemDetail.wrap(0),
            price: price,
            nonce: keccak256(abi.encodePacked(_seller, assetId, block.timestamp))
        });
    }

    // Helper to create listing data with itemDetail
    function _createListingDataWithDetail(
        JJSKIN.AssetId assetId,
        address _seller,
        uint56 price,
        ItemDetail itemDetail
    ) internal view returns (JJSKIN.ListingData memory) {
        return JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: price,
            nonce: keccak256(abi.encodePacked(_seller, assetId, block.timestamp))
        });
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

    // Create EIP-712 signature for testing
    function _signListing(
        JJSKIN.ListingData memory listing,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        // For testing, we'll use vm.sign to create a valid signature
        // The marketplace will recover the signer from this
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));
        
        // Get the domain separator from the marketplace
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
        
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
    
    // Create EIP-712 oracle attestation signature
    function _signOracleAttestation(
        JJSKIN.AssetId assetId,
        ItemDetail itemDetail
    ) internal view returns (bytes memory) {
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

    function _createListingAndPurchase(
        JJSKIN.AssetId assetId,
        address _seller,
        address _buyer,
        uint56 price
    ) internal {
        // Create off-chain listing data
        JJSKIN.ListingData memory listing = _createListingData(assetId, _seller, price);
        // Get the private key for the seller
        uint256 sellerPrivateKey;
        if (_seller == seller) sellerPrivateKey = sellerKey;
        else if (_seller == seller2) sellerPrivateKey = seller2Key;
        else if (_seller == buyer) sellerPrivateKey = buyerKey;
        else if (_seller == buyer2) sellerPrivateKey = buyer2Key;
        else revert("Unknown seller address");
        
        bytes memory signature = _signListing(listing, sellerPrivateKey);
        
        // Buyer purchases with signature
        vm.prank(_buyer);
        marketplace.purchaseWithSignature(listing, _seller, signature);
    }
    
    function _registerWallet(address wallet, uint256 steamId) internal {
        walletFactory.registerForTesting(wallet, steamId);
    }

    // ========== Oracle Settlement Helpers ==========
    // These sign EIP-712 settlements and call submitSettlement

    // Sign an EIP-712 settlement as oracle (includes tradeOfferId for replay protection)
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

    // Sign + submit a single settlement (reads tradeOfferId from purchase)
    function _submitSettlement(JJSKIN.AssetId assetId, uint8 decision, uint8 refundReason) internal {
        uint64 raw = JJSKIN.AssetId.unwrap(assetId);
        (,,, uint48 tradeOfferId) = marketplace.purchases(assetId);
        bytes memory sig = _signSettlement(raw, tradeOfferId, decision, refundReason);
        marketplace.submitSettlement(raw, decision, refundReason, sig);
    }

    // Helper: Settle a single refund via oracle
    function _oracleRefund(JJSKIN.AssetId assetId, JJSKIN.RefundReason reason) internal {
        _submitSettlement(assetId, 1, uint8(reason));
    }

    // Helper: Settle a single release via oracle
    function _oracleClaim(JJSKIN.AssetId assetId) internal {
        _submitSettlement(assetId, 0, 0);
    }

    // Helper: Release multiple assets via oracle (individual calls)
    function _batchReleaseFunds(JJSKIN.AssetId[] memory assetIds) internal {
        for (uint256 i = 0; i < assetIds.length; i++) {
            _oracleClaim(assetIds[i]);
        }
    }

    // Helper to get purchase info
    function _getPurchaseInfo(JJSKIN.AssetId assetId) internal view returns (address buyer, uint40 purchaseTime, JJSKIN.PurchaseStatus status, uint48 tradeOfferId, bool exists) {
        (buyer, purchaseTime, status, tradeOfferId) = marketplace.purchases(assetId);
        exists = buyer != address(0);
    }

    // Helper to get listing seller
    function _getListingSeller(JJSKIN.AssetId assetId) internal view returns (address) {
        (address sellerAddr,,,) = marketplace.listings(assetId);
        return sellerAddr;
    }

    // Helper to get listing price
    function _getListingPrice(JJSKIN.AssetId assetId) internal view returns (uint64) {
        (, uint56 price,,) = marketplace.listings(assetId);
        return uint64(price);
    }
}