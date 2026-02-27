// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/interfaces/IERC4626.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import "./interfaces/ISteamAccountFactory.sol";
import "./interfaces/IERC1271.sol";
import "./interfaces/IAttestationVerifier.sol";
import "./CS2AaveVault.sol";

// ========== User-Defined Value Types (File-Level) ==========
type ItemDetail is uint64;  // Exact item info for listings (20-bit float + paintSeed)
type ItemSpec is uint64;    // Matching criteria for buy orders (10-bit float ranges + tiers)

// ========== ItemDetail Library (Listings) ==========
/**
 * @notice Library for encoding/decoding ItemDetail (exact item information for listings)
 * @dev 64-bit encoding with two modes (auto-detected by encode/decode):
 *
 * STANDARD MODE (paintSeed != 1023) - For items with float (weapons, gloves):
 *   bits 63-48: paintIndex (16 bits) - Skin identifier
 *   bits 47-28: floatValue (20 bits) - Precise float (6 decimals: 0.000000-1.000000)
 *   bits 27-15: defindex (13 bits)   - Weapon type
 *   bits 14-5:  paintSeed (10 bits)  - Exact pattern seed (0-1000)
 *   bits 4-2:   patternTier (3 bits) - Seller-attested tier (0=Any, 1-7=per-skin tiers)
 *   bits 1-0:   quality (2 bits)     - 0=Normal, 1=StatTrak, 2=Souvenir
 *
 * EXTENDED MODE (paintSeed == 1023) - For items without float (stickers, graffiti, agents, etc):
 *   Auto-triggered when defindex > 8191 OR tintId > 0
 *
 *   bits 63-48: 0 (unused)
 *   bits 47-43: tintId (5 bits)      - Graffiti color
 *   bits 42-28: defindex upper (15b) - Upper 15 bits of 28-bit defindex
 *   bits 27-15: defindex lower (13b) - Lower 13 bits of 28-bit defindex
 *   bits 14-5:  1023 (MARKER)        - Extended mode marker (internal)
 *   bits 4-2:   0
 *   bits 1-0:   quality (2 bits)
 *
 *   Smart decode returns clean values:
 *     paintIndex = 0, floatValue = 0, defindex = full 28-bit value
 *     paintSeed = 0 (NOT 1023), tintId = graffiti color
 */
library ItemDetailLib {
    struct Decoded {
        uint16 paintIndex;
        uint32 floatValue;   // 20-bit precise (max 1048575, represents 0.000000-1.000000)
        uint16 defindex;
        uint16 paintSeed;    // Exact seed 0-1000
        uint8 patternTier;   // Per-skin tier (0=Any, 1=best, 7=worst)
        uint8 quality;       // 0=Normal, 1=StatTrak, 2=Souvenir
    }

    function encode(
        uint16 paintIndex,
        uint32 floatValue,  // 20-bit value passed as uint32
        uint16 defindex,    // 13-bit value passed as uint16
        uint16 paintSeed,   // 10-bit value passed as uint16
        uint8 patternTier,  // 3-bit value passed as uint8
        uint8 quality       // 2-bit value passed as uint8
    ) internal pure returns (ItemDetail) {
        uint64 raw = 0;
        raw |= uint64(paintIndex) << 48;
        raw |= uint64(floatValue) << 28;
        raw |= uint64(defindex) << 15;
        raw |= uint64(paintSeed) << 5;
        raw |= uint64(patternTier) << 2;
        raw |= uint64(quality);
        return ItemDetail.wrap(raw);
    }

    function decode(ItemDetail detail) internal pure returns (Decoded memory) {
        uint64 raw = ItemDetail.unwrap(detail);
        return Decoded({
            paintIndex: uint16(raw >> 48),
            floatValue: uint32((raw >> 28) & 0xFFFFF),
            defindex: uint16((raw >> 15) & 0x1FFF),
            paintSeed: uint16((raw >> 5) & 0x3FF),
            patternTier: uint8((raw >> 2) & 0x7),
            quality: uint8(raw & 0x3)
        });
    }

    function getPaintIndex(ItemDetail detail) internal pure returns (uint16) {
        return uint16(ItemDetail.unwrap(detail) >> 48);
    }

    function getFloatValue(ItemDetail detail) internal pure returns (uint32) {
        return uint32((ItemDetail.unwrap(detail) >> 28) & 0xFFFFF);
    }

    function getDefindex(ItemDetail detail) internal pure returns (uint16) {
        return uint16((ItemDetail.unwrap(detail) >> 15) & 0x1FFF);
    }

    function getPaintSeed(ItemDetail detail) internal pure returns (uint16) {
        return uint16((ItemDetail.unwrap(detail) >> 5) & 0x3FF);
    }

    function getPatternTier(ItemDetail detail) internal pure returns (uint8) {
        return uint8((ItemDetail.unwrap(detail) >> 2) & 0x7);
    }

    function getQuality(ItemDetail detail) internal pure returns (uint8) {
        return uint8(ItemDetail.unwrap(detail) & 0x3);
    }

    // ========== Extended Mode (non-float items) ==========

    /// @dev Extended mode marker - paintseed=1023 (impossible in real items, max is 1000)
    uint16 internal constant EXTENDED_MODE_PAINTSEED = 0x3FF;  // 1023

    /// @dev Maximum defindex in extended mode (28 bits)
    uint32 internal constant MAX_EXTENDED_DEFINDEX = 0xFFFFFFF;  // 268,435,455

    /// @notice Decoded extended item (stickers, graffiti, agents, cases, etc)
    struct ExtendedDecoded {
        uint32 defindex;  // Item def_index (28 bits)
        uint8 tintId;     // Graffiti color (5 bits, 0 for non-graffiti)
        uint8 quality;    // 0=Normal, 1=StatTrak (for music kits)
    }

    /// @notice Check if itemDetail is in extended mode
    function isExtendedMode(ItemDetail detail) internal pure returns (bool) {
        uint16 paintSeed = uint16((ItemDetail.unwrap(detail) >> 5) & 0x3FF);
        return paintSeed == EXTENDED_MODE_PAINTSEED;
    }

    /// @notice Encode extended item (non-float items)
    /// @param defindex Item def_index (28 bits max)
    /// @param tintId Graffiti color (5 bits, 0 for non-graffiti)
    /// @param quality 0=Normal, 1=StatTrak (for music kits)
    function encodeExtended(
        uint32 defindex,
        uint8 tintId,
        uint8 quality
    ) internal pure returns (ItemDetail) {
        require(defindex <= MAX_EXTENDED_DEFINDEX, "defindex exceeds 28 bits");

        // Split defindex: upper 15 bits to floatValue, lower 13 bits to defindex position
        uint32 defindexUpper = (defindex >> 13) & 0x7FFF;
        uint32 defindexLower = defindex & 0x1FFF;

        uint64 raw = 0;
        // bits 63-48: 0
        raw |= uint64(tintId & 0x1F) << 43;             // bits 47-43: tintId
        raw |= uint64(defindexUpper) << 28;             // bits 42-28: defindex upper
        raw |= uint64(defindexLower) << 15;             // bits 27-15: defindex lower
        raw |= uint64(EXTENDED_MODE_PAINTSEED) << 5;    // bits 14-5: 1023 (marker)
        raw |= uint64(quality & 0x3);                   // bits 1-0: quality
        return ItemDetail.wrap(raw);
    }

    /// @notice Decode extended item
    function decodeExtended(ItemDetail detail) internal pure returns (ExtendedDecoded memory) {
        require(isExtendedMode(detail), "Not extended mode");
        uint64 raw = ItemDetail.unwrap(detail);

        uint32 floatBits = uint32((raw >> 28) & 0xFFFFF);
        uint16 defindexLower = uint16((raw >> 15) & 0x1FFF);

        uint8 tintId = uint8((floatBits >> 15) & 0x1F);
        uint32 defindexUpper = floatBits & 0x7FFF;
        uint32 defindex = (defindexUpper << 13) | defindexLower;

        return ExtendedDecoded({
            defindex: defindex,
            tintId: tintId,
            quality: uint8(raw & 0x3)
        });
    }

    /// @notice Get defindex from extended mode detail (28 bits)
    function getExtendedDefindex(ItemDetail detail) internal pure returns (uint32) {
        uint64 raw = ItemDetail.unwrap(detail);
        uint32 floatBits = uint32((raw >> 28) & 0xFFFFF);
        uint16 defindexLower = uint16((raw >> 15) & 0x1FFF);
        uint32 defindexUpper = floatBits & 0x7FFF;
        return (defindexUpper << 13) | defindexLower;
    }

    /// @notice Get tintId from extended mode detail
    function getTintId(ItemDetail detail) internal pure returns (uint8) {
        uint64 raw = ItemDetail.unwrap(detail);
        uint32 floatBits = uint32((raw >> 28) & 0xFFFFF);
        return uint8((floatBits >> 15) & 0x1F);
    }
}

// ========== ItemSpec Library (Buy Orders) ==========
/**
 * @notice Library for encoding/decoding ItemSpec (matching criteria for buy orders)
 * @dev 64-bit encoding with float ranges and pattern tier preferences
 * Layout:
 *   bits 63-48: paintIndex (16 bits)  - Skin identifier (must match exactly)
 *   bits 47-38: minFloat (10 bits)    - Range start (3 decimals: 0.000-1.000)
 *   bits 37-28: maxFloat (10 bits)    - Range end (3 decimals: 0.000-1.000)
 *   bits 27-15: defindex (13 bits)    - Weapon type (must match exactly)
 *   bits 14-12: patternTier (3 bits)  - 0=Any, 1-7=specific tier per skin
 *   bits 11-10: quality (2 bits)      - 0=Normal, 1=StatTrak, 2=Souvenir
 *   bits 9-0:   reserved (10 bits)    - Future use
 */
library ItemSpecLib {
    struct Decoded {
        uint16 paintIndex;
        uint16 minFloat;     // 10-bit range start (max 1023, represents 0.000-1.000)
        uint16 maxFloat;     // 10-bit range end
        uint16 defindex;
        uint8 patternTier;   // 0=Any, 1-7=specific tier
        uint8 quality;
    }

    function encode(
        uint16 paintIndex,
        uint16 minFloat,    // 10-bit value passed as uint16
        uint16 maxFloat,    // 10-bit value passed as uint16
        uint16 defindex,    // 13-bit value passed as uint16
        uint8 patternTier,  // 3-bit value passed as uint8
        uint8 quality       // 2-bit value passed as uint8
    ) internal pure returns (ItemSpec) {
        uint64 raw = 0;
        raw |= uint64(paintIndex) << 48;
        raw |= uint64(minFloat) << 38;
        raw |= uint64(maxFloat) << 28;
        raw |= uint64(defindex) << 15;
        raw |= uint64(patternTier) << 12;
        raw |= uint64(quality) << 10;
        // reserved 10 bits (0-9) left as zero
        return ItemSpec.wrap(raw);
    }

    function decode(ItemSpec spec) internal pure returns (Decoded memory) {
        uint64 raw = ItemSpec.unwrap(spec);
        return Decoded({
            paintIndex: uint16(raw >> 48),
            minFloat: uint16((raw >> 38) & 0x3FF),
            maxFloat: uint16((raw >> 28) & 0x3FF),
            defindex: uint16((raw >> 15) & 0x1FFF),
            patternTier: uint8((raw >> 12) & 0x7),
            quality: uint8((raw >> 10) & 0x3)
        });
    }

    function getPaintIndex(ItemSpec spec) internal pure returns (uint16) {
        return uint16(ItemSpec.unwrap(spec) >> 48);
    }

    function getMinFloat(ItemSpec spec) internal pure returns (uint16) {
        return uint16((ItemSpec.unwrap(spec) >> 38) & 0x3FF);
    }

    function getMaxFloat(ItemSpec spec) internal pure returns (uint16) {
        return uint16((ItemSpec.unwrap(spec) >> 28) & 0x3FF);
    }

    function getDefindex(ItemSpec spec) internal pure returns (uint16) {
        return uint16((ItemSpec.unwrap(spec) >> 15) & 0x1FFF);
    }

    function getPatternTier(ItemSpec spec) internal pure returns (uint8) {
        return uint8((ItemSpec.unwrap(spec) >> 12) & 0x7);
    }

    function getQuality(ItemSpec spec) internal pure returns (uint8) {
        return uint8((ItemSpec.unwrap(spec) >> 10) & 0x3);
    }
}

// ========== Matching Library ==========
/**
 * @notice Library for validating ItemDetail against ItemSpec
 * @dev Field-by-field validation with exact matches and range checks
 */
library MatchingLib {
    // Import type definitions from libraries
    using ItemDetailLib for ItemDetail;
    using ItemSpecLib for ItemSpec;

    /**
     * @notice Validate if ItemDetail matches ItemSpec criteria
     * @param detail Exact item information from listing
     * @param spec Matching criteria from buy order
     * @return True if item matches all criteria
     */
    function validateMatch(ItemDetail detail, ItemSpec spec) internal pure returns (bool) {
        ItemDetailLib.Decoded memory d = ItemDetailLib.decode(detail);
        ItemSpecLib.Decoded memory s = ItemSpecLib.decode(spec);

        // 1. EXACT MATCH: defindex, paintIndex, quality
        if (d.defindex != s.defindex) return false;
        if (d.paintIndex != s.paintIndex) return false;
        if (d.quality != s.quality) return false;

        // 2. FLOAT RANGE: Convert 20-bit to 10-bit and check range
        // Shift right 10 bits to convert from 20-bit precision to 10-bit
        uint256 float10bit = uint256(d.floatValue) >> 10;
        if (float10bit < s.minFloat || float10bit > s.maxFloat) return false;

        // 3. PATTERN TIER: Check if spec requires specific tier
        // 0 = Any tier (no preference), 1-7 = specific tier requirement
        if (s.patternTier != 0 && d.patternTier != s.patternTier) return false;

        return true;
    }

    /**
     * @notice Quick check if two ItemSpecs are identical
     * @dev Used for buy order matching optimization
     */
    function specsEqual(ItemSpec spec1, ItemSpec spec2) internal pure returns (bool) {
        return ItemSpec.unwrap(spec1) == ItemSpec.unwrap(spec2);
    }
}

/**
 * @title JJSKIN
 * @author Lumio
 * @notice CS2 marketplace with TEE oracle settlement, escrow, and ERC-4626 yield vault
 * @dev Key features:
 * - TEE-backed oracle: TLSNotary verifier runs inside TEE (Intel TDX/SGX)
 * - Combined Purchase+Escrow into single struct (saves 20k gas)
 * - Oracle-signs-user-submits: Oracle signs EIP-712 settlement, anyone submits on-chain
 * - All platform fees go to treasury
 * - ERC-4626 vault integration for automatic yield generation
 *
 * Trade Flow:
 * 1. Purchase: Buyer pays, funds held in contract
 * 2. TLSNotary: Off-chain proof generation of Steam trade completion
 * 3. TEE Oracle: Verifies proofs inside enclave, signs EIP-712 settlement decision
 * 4. Settlement: Anyone submits oracle-signed decision via submitSettlement()
 * 5. Yield: Idle funds automatically generate yield via ERC-4626 vault
 *
 * Trust Model:
 * - TEE attestation verified at registration (hardware guarantee)
 * - Oracle signs settlement decisions (no gas/RPC needed)
 * - Contract verifies EIP-712 signature against registered oracle set
 * - Treasury only receives fees, cannot control settlements
 */
contract JJSKIN is Ownable2Step, EIP712, ReentrancyGuardTransient, Pausable {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;
    
    // ========== User-Defined Value Types ==========
    type AssetId is uint64;
    type BuyOrderId is uint64;

    // ========== Custom Errors ==========
    error InvalidPrice();
    error AlreadyListed(AssetId assetId);
    error NotSeller(address caller, address actualSeller);
    error InvalidTradeState();
    error InvalidBuyOrderState(BuyOrderState currentState, BuyOrderState expectedState);
    error CannotBuyOwnItem();
    error InvalidInput();
    error NotYourBuyOrder();
    error AlreadyProcessed();
    error NotTreasury();
    error ZeroAddress();
    error NotERC20Token();
    error NotUSDC();
    error CannotWithdrawUSDC();
    error NoPurchaseExists();
    error AlreadyPurchased();
    error TooEarly();                    // 24h timeout not reached
    error SellerAlreadyCommitted();      // Seller committed tradeOfferId, use oracle settlement
    error BuyOrderOverflow();
    error ItemSpecMismatch();
    error NotRegistered();
    error FeeExceedsMaximum(uint256 requested, uint256 maximum);
    error InvalidOracleSignature();
    error NonceInvalid(); // Nonce already used (seller cancelled OR already purchased)
    error NotOracle();
    error VerifierNotSet();
    error InvalidOracleAttestation();
    error AssetAlreadyHasCommitment(AssetId assetId);
    error InvalidSettlementType(uint8 settlementType);

    // ========== Immutables (cannot be changed after deployment) ==========
    IERC20 public immutable usdcToken;
    ISteamAccountFactory public immutable walletFactory;

    // ========== TEE Oracle ==========
    // Oracles run TLSNotary verifier inside TEE (Intel TDX/SGX).
    // Register permissionlessly by providing attestation quote verified on-chain.
    // After registration, any oracle submits settlements (cheap mapping check).
    mapping(address => bool) public oracles;
    IAttestationVerifier public attestationVerifier;

    // ========== Mutable State ==========
    IERC4626 public yieldVault;  // ERC-4626 vault for yield generation (set once after deployment)

    uint256 private constant FEE_DENOMINATOR = 10000;
    uint256 private constant MAX_TOTAL_PRICE = 1e12;       // 1 million USDC max
    uint256 private constant MAX_FEE_PERCENT = 500;        // 5% maximum fee

    // ========== Configurable Time Windows ==========
    uint256 public deliveryWindow = 6 hours;           // Time seller has to send trade offer
    uint256 public abandonedWindow = 24 hours;         // Time before trade considered abandoned
    // EIP-712 type hashes
    bytes32 private constant LISTING_TYPEHASH = keccak256(
        "ListingData(uint64 assetId,uint64 itemDetail,uint56 price,bytes32 nonce)"
    );
    bytes32 private constant ITEM_ATTESTATION_TYPEHASH = keccak256(
        "ItemAttestation(uint64 assetId,uint64 itemDetail)"
    );
    bytes32 private constant SETTLEMENT_TYPEHASH = keccak256(
        "Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)"
    );
    
    // ========== State Variables ==========
    address public treasury;  // Treasury receives remaining platform fees after submitter reward
    uint256 public platformFeePercent = 50; // 0.5% default
    uint64 private _nextBuyOrderId = 1;
    
    // Fee accumulation
    uint256 public accumulatedFees;
    mapping(address => uint256) public withdrawableFees;
    
    // User balance accumulation (both buyers and sellers)
    mapping(address => uint256) public userBalances;
    uint256 public totalUserBalances;  // Track total owed to all users
    
    // Vault tracking (holds both user balances and platform fees for yield)
    uint256 public totalVaultShares;      // Our shares in the yield vault
    uint256 public totalVaultDeposits;    // USDC principal deposited (for yield calculation)
    uint256 public lastYieldHarvest;      // Last time yield was harvested

    // Minimum threshold to deposit to vault (gas optimization)
    uint256 public constant MIN_VAULT_DEPOSIT = 500e6;  // $500 USDC minimum
    
    // ========== Enums ==========
    enum BuyOrderState {
        Active,
        Filled,
        Cancelled
    }

    enum PurchaseStatus {
        Active,     // Trade in progress, funds escrowed
        Released,   // Oracle verified, seller paid
        Refunded    // Refund processed, buyer paid back
    }

    // ========== Structs ==========
    
    // Listing created from off-chain signature
    struct Listing {
        address seller;      // 20 bytes
        uint56 price;        // 7 bytes
        bool exists;         // 1 byte (to differentiate from empty)
        uint32 reserved;     // 4 bytes padding
        // Total: 32 bytes (1 slot)
    }
    
    // Combined Purchase + Escrow (optimized)
    // Settlement verified by TEE oracle via TLSNotary proofs
    struct Purchase {
        address buyer;              // 20 bytes
        uint40 purchaseTime;        // 5 bytes (enough until year 36812)
        PurchaseStatus status;      // 1 byte (enum = uint8)
        uint48 tradeOfferId;        // 6 bytes (max 281 trillion - Steam uses uint64 but 48 bits plenty)
        // Total: 32 bytes (exactly 1 slot, perfect packing)
    }
    
    struct ListingData {
        AssetId assetId;
        ItemDetail itemDetail;  // Exact item info (20-bit float + paintSeed)
        uint56 price;
        bytes32 nonce;
    }
    
    struct BuyOrder {
        address buyer;          // Slot 0: 160 bits
        uint8 quantity;         //         8 bits
        uint8 initialQuantity;  //         8 bits
        BuyOrderState state;    //         8 bits
        uint56 maxPricePerItem; //         56 bits (total 240, 16 wasted)
        ItemSpec itemSpec;      // Slot 1: 64 bits
        uint128 totalSpent;     //         128 bits (total 192, 64 wasted)
    }

    // ========== Settlement Structs ==========

    /// @notice Refund reason enum - matches oracle RefundReason exactly
    /// @dev Values 0-16, with fault attribution for Expired/Canceled/Declined
    enum RefundReason {
        None,               // 0 - Not a refund (Release)
        Timeout,            // 1 - 24h + no commitment (pure on-chain)
        NotCS2Item,         // 2 - appId != 730 (seller's fault)
        WrongAsset,         // 3 - assetId not in trade (seller's fault)
        WrongParties,       // 4 - accountid_other not seller/buyer (seller's fault)
        InvalidItems,       // 5 - GetTradeOffer state 8 (seller's fault)
        Canceled2FA,        // 6 - GetTradeOffer state 10 (seller's fault)
        BuyerExpired,       // 7 - Buyer didn't accept, trade expired (buyer's fault)
        SellerExpired,      // 8 - Seller didn't accept, trade expired (seller's fault)
        BuyerCanceled,      // 9 - Buyer canceled their own offer (buyer's fault)
        SellerCanceled,     // 10 - Seller canceled their own offer (seller's fault)
        BuyerDeclined,      // 11 - Buyer declined seller's offer (buyer's fault)
        SellerDeclined,     // 12 - Seller declined buyer's offer (seller's fault)
        WrongRecipient,     // 13 - GetTradeStatus steamid_other != buyer (seller's fault)
        TradeRollback,      // 14 - GetTradeStatus status 12 (check off-chain who got banned)
        DeprecatedRollback, // 15 - GetTradeStatus deprecated rollback states (4-9, 11)
        TradeNotExist       // 16 - SteamCommunity "does not exist" (seller's fault)
    }

    // ========== Core Mappings ==========
    mapping(AssetId => Listing) public listings;
    mapping(AssetId => Purchase) public purchases;
    mapping(BuyOrderId => BuyOrder) public buyOrders;

    // Buy order tracking
    mapping(AssetId => BuyOrderId) public purchaseFromBuyOrder;

    // Nonce tracking (OpenSea/Blur pattern)
    // Tracks both seller-initiated cancellations AND post-purchase invalidation
    mapping(address => mapping(bytes32 => bool)) public cancelledNonces;

    // Note: tradeOfferCommitments mapping REMOVED - not needed!
    // Commitment is just a signal, oracle verifies actual items in trade via TLSNotary proof
    // The proof's items_to_receive[].assetid is the ground truth, not the commitment
    
    // ========== Events ==========
    event PlatformFeeUpdated(uint256 oldFeePercent, uint256 newFeePercent);

    // Time window update events
    event DeliveryWindowUpdated(uint256 newWindow);
    event AbandonedWindowUpdated(uint256 newWindow);
    
    event ListingConfirmed(AssetId indexed assetId, address indexed seller, uint56 price, ItemDetail itemDetail);
    event ItemPurchased(AssetId indexed assetId, address indexed buyer, uint56 price);
    event FundsReleased(AssetId indexed assetId, address indexed seller, uint256 amount, uint256 fee);
    event PurchaseRefunded(AssetId indexed assetId, address indexed buyer, uint256 amount, RefundReason reason);
    
    event BuyOrderCreated(BuyOrderId indexed orderId, address indexed buyer, ItemSpec itemSpec, uint56 maxPricePerItem, uint8 quantity, uint256 totalLocked);
    event BuyOrderMatched(BuyOrderId indexed orderId, AssetId indexed assetId, address indexed seller, uint56 price);
    event BuyOrderFilled(BuyOrderId indexed orderId, uint8 quantityFilled, uint8 quantityRemaining);
    event BuyOrderCancelled(BuyOrderId indexed orderId, address indexed buyer, uint256 refundAmount);
    
    event UserWithdrawal(address indexed user, uint256 amount);
    event FeesWithdrawn(address indexed recipient, uint256 amount);

    event ListingCancelled(address indexed seller, bytes32 indexed nonce);

    // Trade offer commitment events
    event TradeOfferCommitted(AssetId indexed assetId, uint64 indexed tradeOfferId, address indexed seller);

    // Vault events
    event YieldVaultSet(address indexed vault);
    event FeesDepositedToVault(uint256 amount, uint256 shares);
    event YieldHarvested(uint256 amount);
    event EmergencyVaultWithdrawal(uint256 amount);

    // Treasury events
    event TreasurySet(address indexed treasury);

    // Oracle events
    event OracleRegistered(address indexed oracle);
    event OracleRevoked(address indexed oracle);
    event AttestationVerifierSet(address indexed verifier);
    event SettlementExecuted(AssetId indexed assetId, address indexed submitter, uint8 decision, uint8 refundReason);

    // ========== Modifiers ==========

    modifier requiresFactoryWallet() {
        if (!walletFactory.isRegistered(msg.sender)) revert NotRegistered();
        _;
    }
    
    // ========== Constructor ==========
    constructor(
        address _usdcToken,
        address _walletFactory
    )
        Ownable(msg.sender)
        EIP712("JJSKIN", "1") {
        if (_usdcToken == address(0)) revert ZeroAddress();
        if (_walletFactory == address(0)) revert ZeroAddress();

        // Verify USDC
        try IERC20Metadata(_usdcToken).decimals() returns (uint8 decimals) {
            if (decimals != 6) revert NotUSDC();
        } catch {
            revert NotERC20Token();
        }

        usdcToken = IERC20(_usdcToken);
        walletFactory = ISteamAccountFactory(_walletFactory);

        lastYieldHarvest = block.timestamp;

        // Note: Vault, Treasury, and Oracle will be set by owner after deployment
    }
    
    // ========== View Functions ==========

    /**
     * @notice Get delivery deadline for an asset
     * @dev After this time, refund proof can be submitted if trade not completed
     */
    function getDeliveryDeadline(AssetId assetId) public view returns (uint256) {
        Purchase storage purchase = purchases[assetId];
        if (purchase.buyer == address(0)) return 0;
        return purchase.purchaseTime + deliveryWindow;
    }

    /**
     * @notice Get purchase status for an asset
     * @dev Reverts if no purchase exists to prevent default value (0 = Active) confusion
     */
    function getPurchaseStatus(AssetId assetId) public view returns (PurchaseStatus) {
        if (purchases[assetId].buyer == address(0)) revert NoPurchaseExists();
        return purchases[assetId].status;
    }
    
    // ========== Admin Functions ==========

    function setPlatformFee(uint256 _newFeePercent) external onlyOwner {
        if (_newFeePercent > MAX_FEE_PERCENT) {
            revert FeeExceedsMaximum(_newFeePercent, MAX_FEE_PERCENT);
        }
        uint256 oldFeePercent = platformFeePercent;
        platformFeePercent = _newFeePercent;
        emit PlatformFeeUpdated(oldFeePercent, _newFeePercent);
    }

    function setDeliveryWindow(uint256 _hours) external onlyOwner {
        require(_hours >= 1 hours && _hours <= 48 hours, "Invalid delivery window");
        deliveryWindow = _hours;
        emit DeliveryWindowUpdated(_hours);
    }
    
    function setAbandonedWindow(uint256 _hours) external onlyOwner {
        require(_hours >= 12 hours && _hours <= 72 hours, "Invalid abandoned window");
        abandonedWindow = _hours;
        emit AbandonedWindowUpdated(_hours);
    }
    

    // ========== Pause Functions ==========

    /// @notice Pause new purchases, buy orders, and commitments (emergency circuit breaker)
    /// @dev Exits stay open: withdrawBalance, cancelBuyOrder, cancelListing, settlements
    function pause() external onlyOwner { _pause(); }

    /// @notice Resume normal operations
    function unpause() external onlyOwner { _unpause(); }

    // ========== Treasury Functions ==========

    /**
     * @notice Set the treasury address for platform fee collection
     * @dev Treasury is purely for fee collection - no control over settlements.
     * @param _treasury Address to receive all platform fees
     */
    function setTreasury(address _treasury) external onlyOwner {
        if (_treasury == address(0)) revert ZeroAddress();

        // Migrate pending fees to new treasury (prevents orphaning)
        uint256 pending = withdrawableFees[treasury];
        if (pending > 0) {
            withdrawableFees[treasury] = 0;
            withdrawableFees[_treasury] = pending;
        }

        treasury = _treasury;
        emit TreasurySet(_treasury);
    }

    // ========== Oracle Registration Functions ==========

    /**
     * @notice Set the attestation verifier contract
     * @dev Owner sets the verifier that validates TEE attestation quotes.
     *      Can be updated to support new TEE platforms (TDX, SGX, etc.)
     * @param _verifier Address of the IAttestationVerifier implementation
     */
    function setAttestationVerifier(address _verifier) external onlyOwner {
        if (_verifier == address(0)) revert ZeroAddress();
        attestationVerifier = IAttestationVerifier(_verifier);
        emit AttestationVerifierSet(_verifier);
    }

    /**
     * @notice Register oracle via TEE attestation (permissionless)
     * @dev Anyone with a valid TEE attestation can register as oracle.
     *      The verifier checks attestation validity and extracts the signing address.
     *      Called once per TEE boot cycle. Multiple oracles can be registered.
     *
     *      NOTE: On-chain DCAP verification requires Intel collateral (TCB info, PCK certs)
     *      to be registered on the Automata on-chain PCCS for the specific TDX platform.
     *      If collateral is not available, use registerOracleDirect() as a fallback.
     *
     *      Future upgrade: ZK-based DCAP verification (RISC Zero / SP1) eliminates
     *      the collateral requirement entirely. See: https://github.com/automata-network/tdx-attestation-sdk
     *
     * @param attestation Raw attestation data (TDX quote, SGX DCAP, etc.)
     */
    function registerOracle(bytes calldata attestation) external nonReentrant {
        if (address(attestationVerifier) == address(0)) revert VerifierNotSet();
        address oracleAddress = attestationVerifier.verifyAttestation(attestation);
        oracles[oracleAddress] = true;
        emit OracleRegistered(oracleAddress);
    }

    /**
     * @notice Register oracle directly by address (owner only)
     * @dev Fallback for when on-chain DCAP verification is unavailable (e.g. missing
     *      Intel collateral on the Automata on-chain PCCS for this TDX platform).
     *
     *      The TDX attestation quote is still publicly verifiable off-chain via:
     *        - Phala Trust Center: https://trust.phala.com
     *        - TEE Attestation Explorer: https://proof.t16z.com
     *        - dcap-qvl (Rust): https://github.com/Phala-Network/dcap-qvl
     *
     *      Anyone can fetch the quote from the oracle's /attestation endpoint and
     *      independently verify the MRTD, RTMR[3], and oracle address match.
     *
     *      Intended to be replaced by registerOracle() once ZK-based DCAP verification
     *      is production-ready (RISC Zero / SP1 path).
     *
     * @param oracleAddress The oracle's Ethereum address (from TDX reportData)
     */
    function registerOracleDirect(address oracleAddress) external onlyOwner {
        if (oracleAddress == address(0)) revert ZeroAddress();
        oracles[oracleAddress] = true;
        emit OracleRegistered(oracleAddress);
    }

    /**
     * @notice Revoke a registered oracle (owner only)
     * @dev Used when a TEE instance is compromised or decommissioned.
     * @param oracleAddress The oracle address to revoke
     */
    function revokeOracle(address oracleAddress) external onlyOwner {
        if (!oracles[oracleAddress]) revert NotOracle();
        oracles[oracleAddress] = false;
        emit OracleRevoked(oracleAddress);
    }

    // ========== Oracle Settlement Functions ==========

    /**
     * @notice Submit a single settlement with oracle EIP-712 signature
     * @dev Anyone can call — oracle authority is verified via signature.
     *      Oracle signs the settlement decision off-chain (EIP-712), caller submits on-chain.
     *      This removes the need for the oracle to have gas, RPC, or wallet management.
     *
     *      Idempotent: silently returns if already settled.
     *
     * @param assetId The Steam asset ID
     * @param decision 0 = release (seller paid), 1 = refund (buyer refunded)
     * @param refundReason RefundReason enum value (0 if release)
     * @param oracleSignature EIP-712 signature from a registered oracle
     */
    function submitSettlement(
        uint64 assetId,
        uint8 decision,
        uint8 refundReason,
        bytes calldata oracleSignature
    ) external nonReentrant {
        // 1. Load purchase first (need tradeOfferId for signature verification)
        AssetId aid = AssetId.wrap(assetId);
        Purchase storage purchase = purchases[aid];

        // Verify trade was committed
        if (purchase.tradeOfferId == 0) revert NoPurchaseExists();

        // 2. Verify oracle signature (EIP-712, includes tradeOfferId to prevent replay after refund+relist)
        bytes32 structHash = keccak256(abi.encode(
            SETTLEMENT_TYPEHASH, assetId, uint48(purchase.tradeOfferId), decision, refundReason
        ));
        address recovered = ECDSA.recover(_hashTypedDataV4(structHash), oracleSignature);
        if (!oracles[recovered]) revert InvalidOracleSignature();

        // Skip if already settled (idempotent)
        if (purchase.status != PurchaseStatus.Active) return;

        // 3. Validate decision + refundReason consistency
        if (decision > 1) revert InvalidSettlementType(decision);
        if (decision == 0 && refundReason != 0) revert InvalidInput();

        // 4. Execute settlement
        Listing storage listing = listings[aid];
        uint56 price = listing.price;

        if (decision == 0) {
            // Release — seller gets paid (minus platform fee)
            purchase.status = PurchaseStatus.Released;
            uint256 fee = (uint256(price) * platformFeePercent) / FEE_DENOMINATOR;
            uint256 sellerAmount = uint256(price) - fee;
            address sellerAddr = listing.seller;
            userBalances[sellerAddr] += sellerAmount;
            totalUserBalances += sellerAmount;
            if (fee > 0) {
                withdrawableFees[treasury] += fee;
                accumulatedFees += fee;
            }
            emit FundsReleased(aid, sellerAddr, sellerAmount, fee);
        } else {
            // Refund — buyer gets money back
            purchase.status = PurchaseStatus.Refunded;

            // Clear listing to allow re-listing
            delete listings[aid];

            // Refund to buyer's balance (no buy order restoration — avoids
            // surplus claw-back underflow if buyer already withdrew surplus)
            userBalances[purchase.buyer] += price;
            totalUserBalances += price;

            emit PurchaseRefunded(aid, purchase.buyer, price, RefundReason(refundReason));
        }

        emit SettlementExecuted(aid, msg.sender, decision, refundReason);
    }

    /**
     * @notice Pure on-chain timeout refund (no oracle needed)
     * @dev Anyone can trigger refund if:
     *      1. 24 hours have passed since purchase
     *      2. Seller has NOT committed a tradeOfferId
     *      This gives seller 24h to commit, otherwise anyone can trigger refund.
     *      Funds always go to buyer, caller just triggers the refund.
     *
     * @param assetId The asset to refund
     */
    function claimTimeoutRefund(AssetId assetId) external nonReentrant {
        Purchase storage purchase = purchases[assetId];
        Listing storage listing = listings[assetId];

        // Must be active purchase
        if (purchase.status != PurchaseStatus.Active) revert InvalidTradeState();

        // Abandoned window must have passed
        if (block.timestamp <= purchase.purchaseTime + abandonedWindow) {
            revert TooEarly();
        }

        // Seller must NOT have committed a tradeOfferId
        // If seller committed, buyer must use oracle settlement to claim refund
        if (purchase.tradeOfferId != 0) {
            revert SellerAlreadyCommitted();
        }

        // Execute refund
        uint256 refundAmount = listing.price;
        purchase.status = PurchaseStatus.Refunded;

        // Clear listing to allow re-listing
        delete listings[assetId];

        // Refund to buyer's balance (no buy order restoration — avoids
        // surplus claw-back underflow if buyer already withdrew surplus)
        userBalances[purchase.buyer] += refundAmount;
        totalUserBalances += refundAmount;

        emit PurchaseRefunded(assetId, purchase.buyer, refundAmount, RefundReason.Timeout);
    }

    // ========== Vault Functions ==========

    /**
     * @notice Set the yield vault address
     * @dev Can only be called once to set the vault after deployment
     * @param _vault Address of the ERC-4626 vault
     */
    function setYieldVault(address _vault) external onlyOwner {
        if (address(yieldVault) != address(0)) revert AlreadyProcessed();
        if (_vault == address(0)) revert ZeroAddress();
        
        yieldVault = IERC4626(_vault);
        
        // Approve vault to spend USDC
        usdcToken.forceApprove(_vault, type(uint256).max);
        
        emit YieldVaultSet(_vault);
    }
    
    /**
     * @notice Deposit idle USDC to yield vault
     * @dev Deposits all idle funds (escrow + balances) above minimum threshold
     * The vault's 10% buffer handles liquidity for withdrawals/refunds
     */
    function depositIdleFundsToVault() external onlyOwner nonReentrant returns (uint256 shares) {
        if (address(yieldVault) == address(0)) revert InvalidInput();

        // Total USDC in contract (includes escrow, userBalances, and fees)
        uint256 contractBalance = usdcToken.balanceOf(address(this));

        // Only deposit if above minimum threshold (gas optimization)
        if (contractBalance < MIN_VAULT_DEPOSIT) revert InvalidInput();

        // Keep 10% liquid for immediate withdrawals/refunds
        uint256 bufferAmount = contractBalance / 10;
        uint256 depositAmount = contractBalance - bufferAmount;

        if (depositAmount == 0) revert InvalidInput();

        // Deposit to vault and track shares + principal
        shares = yieldVault.deposit(depositAmount, address(this));
        totalVaultShares += shares;
        totalVaultDeposits += depositAmount;

        emit FeesDepositedToVault(depositAmount, shares);
    }
    
    /**
     * @notice Harvest yield from vault for treasury
     * @dev Uses vault's harvestYield which correctly tracks deposited principal.
     *      Yield goes 100% to treasury (not split with submitter).
     */
    function harvestYield() external nonReentrant returns (uint256 yieldAmount) {
        if (address(yieldVault) == address(0)) revert InvalidInput();

        // Use vault's built-in harvest which tracks totalDeposited correctly
        // This avoids the shares != deposited USDC issue after price changes
        yieldAmount = CS2AaveVault(address(yieldVault)).harvestYield(address(this));

        if (yieldAmount > 0) {
            // Add yield to treasury (yield is passive income, no submitter reward)
            withdrawableFees[treasury] += yieldAmount;
            accumulatedFees += yieldAmount;

            lastYieldHarvest = block.timestamp;
            emit YieldHarvested(yieldAmount);
        }
    }
    
    /**
     * @notice Emergency withdraw all funds from vault
     * @dev Only owner can call in case of vault issues
     * Funds return to contract, maintaining existing balance accounting
     */
    function emergencyWithdrawFromVault() external onlyOwner nonReentrant {
        if (address(yieldVault) == address(0)) revert InvalidInput();
        if (totalVaultShares == 0) revert InvalidInput();

        // Redeem all shares
        uint256 withdrawn = yieldVault.redeem(
            totalVaultShares,
            address(this),
            address(this)
        );

        // Reset vault tracking - funds are now back in contract
        totalVaultShares = 0;
        totalVaultDeposits = 0;

        emit EmergencyVaultWithdrawal(withdrawn);
    }
    
    /**
     * @notice Withdraw accumulated platform fees to treasury
     * @dev Only treasury can withdraw. All platform fees go to treasury.
     */
    function withdrawFees() external nonReentrant returns (uint256 amount) {
        if (msg.sender != treasury) revert NotTreasury();

        amount = withdrawableFees[treasury];
        if (amount == 0) revert InvalidInput();

        withdrawableFees[treasury] = 0;
        accumulatedFees -= amount;

        usdcToken.safeTransfer(treasury, amount);
        emit FeesWithdrawn(treasury, amount);
    }
    
    /**
     * @notice Withdraw user balance
     * @dev Users (buyers/sellers) withdraw their accumulated balance
     * Pulls from vault if contract doesn't have enough liquid USDC
     */
    function withdrawBalance() external nonReentrant returns (uint256 amount) {
        amount = userBalances[msg.sender];
        if (amount == 0) revert InvalidInput();

        userBalances[msg.sender] = 0;
        totalUserBalances -= amount;

        // Check if we have enough USDC in contract
        uint256 contractBalance = usdcToken.balanceOf(address(this));
        if (contractBalance < amount) {
            // Try to withdraw from vault if we have shares there
            if (address(yieldVault) != address(0) && totalVaultShares > 0) {
                uint256 needed = amount - contractBalance;
                uint256 vaultAssets = yieldVault.convertToAssets(totalVaultShares);

                if (vaultAssets >= needed) {
                    // Use withdraw() which takes exact asset amount (avoids convertToShares rounding)
                    uint256 sharesBefore = yieldVault.balanceOf(address(this));
                    yieldVault.withdraw(needed, address(this), address(this));
                    uint256 sharesUsed = sharesBefore - yieldVault.balanceOf(address(this));

                    // Update vault tracking (proportional reduction)
                    uint256 depositReduction = totalVaultDeposits * sharesUsed / totalVaultShares;
                    totalVaultShares -= sharesUsed;
                    totalVaultDeposits = totalVaultDeposits > depositReduction ? totalVaultDeposits - depositReduction : 0;

                    // Update contract balance
                    contractBalance = usdcToken.balanceOf(address(this));
                }
            }

            // If still insufficient after vault withdrawal, revert
            if (contractBalance < amount) {
                revert InvalidInput();
            }
        }

        usdcToken.safeTransfer(msg.sender, amount);
        emit UserWithdrawal(msg.sender, amount);
    }
    
    /**
     * @notice Get available balance for a user
     */
    function getUserBalance(address user) external view returns (uint256) {
        return userBalances[user];
    }

    // ========== Listing Cancellation Functions ==========

    /**
     * @notice Cancel a single listing by marking its nonce as cancelled
     * @dev Prevents signature replay attacks when seller wants to update price or delist
     * @param nonce The nonce of the listing to cancel
     */
    function cancelListing(bytes32 nonce) external {
        cancelledNonces[msg.sender][nonce] = true;
        emit ListingCancelled(msg.sender, nonce);
    }

    /**
     * @notice Cancel multiple listings in one transaction
     * @dev More gas efficient than multiple individual cancellations
     * @param nonces Array of nonces to cancel
     */
    function cancelListings(bytes32[] calldata nonces) external {
        uint256 length = nonces.length;
        for (uint256 i = 0; i < length; i++) {
            cancelledNonces[msg.sender][nonces[i]] = true;
            emit ListingCancelled(msg.sender, nonces[i]);
        }
    }

    /**
     * @notice Check if a listing nonce is cancelled/invalid for a seller
     * @dev Returns true if seller cancelled OR if nonce already used in a purchase
     * @param seller The seller address
     * @param nonce The nonce to check
     */
    function isListingCancelled(address seller, bytes32 nonce) external view returns (bool) {
        return cancelledNonces[seller][nonce];
    }

    // ========== Trade Offer Commitment Functions ==========

    /**
     * @notice Seller commits their Steam trade offer ID after sending the trade
     * @dev Stores tradeOfferId in purchase record. Without commitment, buyer can auto-refund after 24h.
     *      tradeOfferId is included in the EIP-712 settlement signature to prevent replay.
     * @param assetId The asset being traded
     * @param tradeOfferId The Steam trade offer ID (uint64, fits in uint48 storage)
     */
    function commitTradeOffer(AssetId assetId, uint64 tradeOfferId) external whenNotPaused {
        Listing storage listing = listings[assetId];
        Purchase storage purchase = purchases[assetId];

        // Must be seller of this listing
        if (listing.seller != msg.sender) revert NotSeller(msg.sender, listing.seller);

        // Must have active purchase (catches already refunded/released)
        if (purchase.buyer == address(0)) revert NoPurchaseExists();
        if (purchase.status != PurchaseStatus.Active) revert InvalidTradeState();

        // Validate tradeOfferId (0 = no commitment; must fit uint48 storage)
        if (tradeOfferId == 0 || tradeOfferId > type(uint48).max) revert InvalidInput();

        // Asset must not already have a commitment
        if (purchase.tradeOfferId != 0) {
            revert AssetAlreadyHasCommitment(assetId);
        }

        // Record tradeOfferId
        purchase.tradeOfferId = uint48(tradeOfferId);

        emit TradeOfferCommitted(assetId, tradeOfferId, msg.sender);
    }

    /**
     * @notice Check if a trade offer commitment exists for an asset
     * @param assetId The asset to check
     * @return tradeOfferId The committed trade offer ID (0 if none)
     */
    function getTradeOfferCommitment(uint64 assetId) external view returns (uint48 tradeOfferId) {
        return purchases[AssetId.wrap(assetId)].tradeOfferId;
    }

    /**
     * @notice Check if commitment deadline has passed for an asset
     * @dev Used by refund logic: if deadline passed and no commitment, auto-refund
     * @param assetId The asset to check
     * @return passed True if commitment deadline has passed
     * @return hasCommitment True if a commitment exists
     */
    function isCommitmentDeadlinePassed(uint64 assetId) external view returns (bool passed, bool hasCommitment) {
        Purchase storage purchase = purchases[AssetId.wrap(assetId)];

        if (purchase.buyer == address(0)) return (false, false);

        uint256 deadline = purchase.purchaseTime + deliveryWindow;
        passed = block.timestamp > deadline;
        hasCommitment = purchase.tradeOfferId != 0;
    }

    /**
     * @notice Get batch asset information for multiple assets
     * @dev Used by VerifierNetwork for efficient batch creation
     * @param assetIds Array of asset IDs to query
     * @return prices Listing prices for each asset
     * @return purchaseTimes When each purchase was created
     * @return statuses Current status of each purchase
     */
    function getBatchAssetInfo(uint64[] calldata assetIds)
        external
        view
        returns (
            uint56[] memory prices,
            uint40[] memory purchaseTimes,
            PurchaseStatus[] memory statuses,
            bool[] memory exists
        )
    {
        uint256 len = assetIds.length;
        prices = new uint56[](len);
        purchaseTimes = new uint40[](len);
        statuses = new PurchaseStatus[](len);
        exists = new bool[](len);

        for (uint256 i = 0; i < len; i++) {
            AssetId assetId = AssetId.wrap(assetIds[i]);
            Listing storage listing = listings[assetId];
            Purchase storage purchase = purchases[assetId];

            prices[i] = listing.price;
            purchaseTimes[i] = purchase.purchaseTime;
            exists[i] = purchase.buyer != address(0);
            statuses[i] = purchase.status;
        }
    }

    /**
     * @notice Get the seller address for a listing
     * @param assetId The asset to check
     * @return seller The seller's address (zero if no listing)
     */
    function getSellerAddress(uint64 assetId) external view returns (address seller) {
        return listings[AssetId.wrap(assetId)].seller;
    }

    /**
     * @notice Check if a purchase exists and is active
     * @param assetId The asset to check
     * @return True if purchase exists and is Active
     */
    function isPurchaseActive(uint64 assetId) external view returns (bool) {
        Purchase storage purchase = purchases[AssetId.wrap(assetId)];
        return purchase.buyer != address(0) && purchase.status == PurchaseStatus.Active;
    }

    // TODO: Batch operations for fungible items (cases, keys, etc.)
    // Fungible items have no unique float/paint/seed, so N identical items share one itemDetail.
    // - Batch listing: one EIP-712 signature covers N identical items (same itemDetail + price)
    // - Batch purchase: buyer purchases N items in one tx (single USDC transfer for total)
    // - Batch commit: one tradeOfferId for a multi-item Steam trade
    // - Batch settlement: oracle signs once for all N items (all-or-nothing release/refund)
    // Restrict to fungible items only — items with float/paint/seed must use single-item flow.

    // ========== Purchase Functions ==========
    
    /**
     * @notice Purchase with off-chain listing signature
     * @dev Creates listing on-chain and locks funds in escrow
     */
    function purchaseWithSignature(
        ListingData calldata listing,
        address seller,
        bytes calldata signature
    ) external nonReentrant requiresFactoryWallet whenNotPaused {
        // Validations
        if (!walletFactory.isRegistered(seller)) revert NotRegistered();
        _verifyListingSignature(listing, signature, seller);

        // Check nonce not already used (OpenSea/Blur pattern)
        if (cancelledNonces[seller][listing.nonce]) revert NonceInvalid();
        if (seller == msg.sender) revert CannotBuyOwnItem();
        if (listing.price == 0) revert InvalidPrice();
        // Layer 2: Prevents different-nonce listings for the same assetId (nonce system only prevents same-signature replay)
        if (listings[listing.assetId].exists) revert AlreadyListed(listing.assetId);
        // Layer 3: Defense-in-depth — guards against listing.exists being cleared without settling the purchase
        if (purchases[listing.assetId].buyer != address(0) && purchases[listing.assetId].status == PurchaseStatus.Active) revert AlreadyPurchased();

        // Mark nonce as cancelled (prevents reuse by seller or replay by buyer)
        cancelledNonces[seller][listing.nonce] = true;

        // Create on-chain listing + purchase atomically (keeps listing.exists and purchase.Active in sync)
        listings[listing.assetId] = Listing({
            seller: seller,
            price: listing.price,
            exists: true,
            reserved: 0
        });

        purchases[listing.assetId] = Purchase({
            buyer: msg.sender,
            purchaseTime: uint40(block.timestamp),
            status: PurchaseStatus.Active,
            tradeOfferId: 0
        });
        
        // Handle payment - use balance first, then pull remainder from wallet
        // Backend should calculate: approvalAmount = max(0, price - userBalance)
        uint256 price = listing.price;
        uint256 buyerBalance = userBalances[msg.sender];
        
        if (buyerBalance >= price) {
            // Sufficient balance - use it entirely
            userBalances[msg.sender] -= price;
            totalUserBalances -= price;
        } else if (buyerBalance > 0) {
            // Partial balance - use it and pull remainder
            uint256 remainder = price - buyerBalance;
            userBalances[msg.sender] = 0;
            totalUserBalances -= buyerBalance;
            usdcToken.safeTransferFrom(msg.sender, address(this), remainder);
        } else {
            // No balance - pull entire amount
            usdcToken.safeTransferFrom(msg.sender, address(this), price);
        }
        
        emit ItemPurchased(listing.assetId, msg.sender, listing.price);
        emit ListingConfirmed(listing.assetId, seller, listing.price, listing.itemDetail);
    }
    
    // ========== Buy Order Functions ==========
    
    function createBuyOrder(
        ItemSpec itemSpec,
        uint56 maxPricePerItem,
        uint8 quantity
    ) external nonReentrant requiresFactoryWallet whenNotPaused returns (BuyOrderId) {
        if (maxPricePerItem == 0 || quantity == 0) revert InvalidInput();

        uint256 totalAmount = uint256(maxPricePerItem) * uint256(quantity);
        if (totalAmount > MAX_TOTAL_PRICE) revert BuyOrderOverflow();

        BuyOrderId orderId = BuyOrderId.wrap(_nextBuyOrderId++);

        buyOrders[orderId] = BuyOrder({
            buyer: msg.sender,
            itemSpec: itemSpec,
            maxPricePerItem: maxPricePerItem,
            quantity: quantity,
            initialQuantity: quantity,
            totalSpent: 0,
            state: BuyOrderState.Active
        });

        // Handle payment: try userBalance first, then pull from wallet
        uint256 buyerBalance = userBalances[msg.sender];
        if (buyerBalance >= totalAmount) {
            // Use entire balance
            userBalances[msg.sender] -= totalAmount;
            totalUserBalances -= totalAmount;
        } else if (buyerBalance > 0) {
            // Use partial balance + wallet
            userBalances[msg.sender] = 0;
            totalUserBalances -= buyerBalance;
            uint256 remainder = totalAmount - buyerBalance;
            usdcToken.safeTransferFrom(msg.sender, address(this), remainder);
        } else {
            // No balance - pull entire amount from wallet
            usdcToken.safeTransferFrom(msg.sender, address(this), totalAmount);
        }

        emit BuyOrderCreated(orderId, msg.sender, itemSpec, maxPricePerItem, quantity, totalAmount);
        return orderId;
    }
    
    function cancelBuyOrder(BuyOrderId orderId) external nonReentrant {
        BuyOrder storage order = buyOrders[orderId];

        if (order.buyer != msg.sender) revert NotYourBuyOrder();
        if (order.state != BuyOrderState.Active) {
            revert InvalidBuyOrderState(order.state, BuyOrderState.Active);
        }

        uint256 totalLocked = uint256(order.maxPricePerItem) * uint256(order.initialQuantity);
        uint256 refundAmount = totalLocked - order.totalSpent;

        order.state = BuyOrderState.Cancelled;
        order.quantity = 0;

        if (refundAmount > 0) {
            // Add to userBalance instead of direct transfer
            userBalances[msg.sender] += refundAmount;
            totalUserBalances += refundAmount;
        }

        emit BuyOrderCancelled(orderId, msg.sender, refundAmount);
    }
    
    function executeBuyOrderMatchWithSignature(
        BuyOrderId orderId,
        ListingData calldata listing,
        address seller,
        bytes calldata signature,
        bytes calldata oracleAttestation
    ) external nonReentrant whenNotPaused {
        BuyOrder storage order = buyOrders[orderId];

        // Validate order
        if (order.state != BuyOrderState.Active) revert InvalidBuyOrderState(order.state, BuyOrderState.Active);
        if (order.quantity == 0) revert InvalidInput();

        // Validate listing
        if (!walletFactory.isRegistered(seller)) revert NotRegistered();
        _verifyListingSignature(listing, signature, seller);

        // Verify oracle attestation (TEE oracle confirms item details)
        _verifyOracleAttestation(listing.assetId, listing.itemDetail, oracleAttestation);

        // Check nonce not already used (OpenSea/Blur pattern)
        if (cancelledNonces[seller][listing.nonce]) revert NonceInvalid();
        if (seller == order.buyer) revert CannotBuyOwnItem();
        // Validate ItemDetail matches ItemSpec criteria (field-by-field validation)
        if (!MatchingLib.validateMatch(listing.itemDetail, order.itemSpec)) revert ItemSpecMismatch();
        if (listing.price == 0 || listing.price > order.maxPricePerItem) revert InvalidPrice();
        // Layer 2: Prevents different-nonce listings for the same assetId
        if (listings[listing.assetId].exists) revert AlreadyListed(listing.assetId);
        // Layer 3: Defense-in-depth — guards against listing.exists being cleared without settling the purchase
        if (purchases[listing.assetId].buyer != address(0) && purchases[listing.assetId].status == PurchaseStatus.Active) revert AlreadyPurchased();

        // Mark nonce as cancelled (prevents reuse by seller or replay by buyer)
        cancelledNonces[seller][listing.nonce] = true;

        // Create listing + purchase atomically (keeps listing.exists and purchase.Active in sync)
        listings[listing.assetId] = Listing({
            seller: seller,
            price: listing.price,
            exists: true,
            reserved: 0
        });

        order.totalSpent += listing.price;
        order.quantity--;

        purchases[listing.assetId] = Purchase({
            buyer: order.buyer,
            purchaseTime: uint40(block.timestamp),
            status: PurchaseStatus.Active,
            tradeOfferId: 0
        });
        
        purchaseFromBuyOrder[listing.assetId] = orderId;
        
        emit ItemPurchased(listing.assetId, order.buyer, listing.price);
        emit BuyOrderMatched(orderId, listing.assetId, seller, listing.price);
        emit ListingConfirmed(listing.assetId, seller, listing.price, listing.itemDetail);
        
        // Handle order completion
        if (order.quantity == 0) {
            order.state = BuyOrderState.Filled;

            uint256 totalLocked = uint256(order.maxPricePerItem) * uint256(order.initialQuantity);
            uint256 refund = totalLocked - order.totalSpent;

            if (refund > 0) {
                // Add to userBalance instead of direct transfer
                userBalances[order.buyer] += refund;
                totalUserBalances += refund;
            }

            emit BuyOrderFilled(orderId, order.initialQuantity, 0);
        } else {
            emit BuyOrderFilled(orderId, 1, order.quantity);
        }
    }
    
    // ========== Internal Functions ==========

    function _verifyOracleAttestation(
        AssetId assetId,
        ItemDetail itemDetail,
        bytes calldata oracleAttestation
    ) internal view {
        bytes32 structHash = keccak256(abi.encode(
            ITEM_ATTESTATION_TYPEHASH,
            AssetId.unwrap(assetId),
            ItemDetail.unwrap(itemDetail)
        ));

        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, oracleAttestation);
        if (!oracles[recovered]) revert InvalidOracleAttestation();
    }

    function _verifyListingSignature(
        ListingData calldata listing,
        bytes calldata signature,
        address seller
    ) internal view {
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));
        
        bytes32 digest = _hashTypedDataV4(structHash);
        
        // Validate with smart account
        try IERC1271(seller).isValidSignature(digest, signature) returns (bytes4 magicValue) {
            if (magicValue != 0x1626ba7e) {
                revert InvalidInput();
            }
        } catch {
            revert InvalidInput();
        }
    }
    
    // ========== Emergency Functions ==========
    
    function rescueERC20(address token, uint256 amount) external onlyOwner {
        if (token == address(usdcToken)) revert CannotWithdrawUSDC();
        IERC20(token).safeTransfer(owner(), amount);
    }
}