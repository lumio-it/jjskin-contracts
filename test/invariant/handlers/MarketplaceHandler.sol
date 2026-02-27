// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import {JJSKIN, ItemDetail, ItemSpec, ItemDetailLib, ItemSpecLib} from "../../../src/JJSKIN.sol";
import {MockUSDC} from "../../../src/mocks/MockUSDC.sol";

/// @title MarketplaceHandler
/// @notice Stateful handler for invariant testing of JJSKIN marketplace
/// @dev Ghost variables track expected state for invariant assertions
contract MarketplaceHandler is Test {
    JJSKIN public marketplace;
    MockUSDC public usdc;

    // Test actors
    address public seller;
    address public buyer;
    address public seller2;
    address public buyer2;

    // Private keys for signing
    uint256 public sellerKey;
    uint256 public buyerKey;
    uint256 public seller2Key;
    uint256 public buyer2Key;

    // Oracle signing
    uint256 public oracleKey;
    address public oracleAddr;

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

    // ========== Ghost Variables ==========
    uint256 public ghost_totalEscrowed;             // Sum of active purchase prices
    uint256 public ghost_totalDirectTransfers;      // USDC sent to orchestrators (unused, kept for compat)
    uint256 public ghost_feeConservationViolations; // Fee math error counter
    uint256 public ghost_buyOrderLocked;            // Total locked in active buy orders (unallocated portion)

    // Success/failure ghost counters
    uint256 public ghost_purchase_success;
    uint256 public ghost_purchase_fail;
    uint256 public ghost_commit_success;
    uint256 public ghost_commit_fail;
    uint256 public ghost_settle_release_success;
    uint256 public ghost_settle_release_fail;
    uint256 public ghost_settle_refund_success;
    uint256 public ghost_settle_refund_fail;
    uint256 public ghost_buyOrder_success;
    uint256 public ghost_buyOrder_fail;
    uint256 public ghost_buyOrderMatch_success;
    uint256 public ghost_buyOrderMatch_fail;
    uint256 public ghost_relistSuccess;
    uint256 public ghost_relistFail;
    uint256 public ghost_timeoutRefund_success;
    uint256 public ghost_timeoutRefund_fail;

    // ========== Asset Tracking Pools ==========
    uint64[] public uncommittedAssets;   // Active purchases without commitment
    uint64[] public committedAssets;     // Active purchases with commitment
    uint64[] public refundedAssets;      // Refunded asset IDs (available for re-listing)
    uint64[] public releasedAssets;      // Released asset IDs (listing persists, NOT relistable)
    JJSKIN.BuyOrderId[] public activeBuyOrders;

    // Track all users who have interacted (for balance summation)
    address[] public trackedUsers;
    mapping(address => bool) public isTracked;

    // Counters for unique asset IDs and nonces
    uint64 private _nextAssetId = 1;
    uint64 private _nextNonce = 1;

    constructor(
        JJSKIN _marketplace,
        MockUSDC _usdc,
        address _seller,
        address _buyer,
        address _seller2,
        address _buyer2,
        uint256 _sellerKey,
        uint256 _buyerKey,
        uint256 _seller2Key,
        uint256 _buyer2Key,
        uint256 _oracleKey,
        address _oracleAddr
    ) {
        marketplace = _marketplace;
        usdc = _usdc;
        seller = _seller;
        buyer = _buyer;
        seller2 = _seller2;
        buyer2 = _buyer2;
        sellerKey = _sellerKey;
        buyerKey = _buyerKey;
        seller2Key = _seller2Key;
        buyer2Key = _buyer2Key;
        oracleKey = _oracleKey;
        oracleAddr = _oracleAddr;

        _trackUser(seller);
        _trackUser(buyer);
        _trackUser(seller2);
        _trackUser(buyer2);
    }

    // ========== Internal Helpers ==========

    function _trackUser(address user) internal {
        if (!isTracked[user]) {
            trackedUsers.push(user);
            isTracked[user] = true;
        }
    }

    function _buildDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("JJSKIN"),
                keccak256("1"),
                block.chainid,
                address(marketplace)
            )
        );
    }

    function _signListing(
        JJSKIN.ListingData memory listing,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signOracleAttestation(
        JJSKIN.AssetId assetId,
        ItemDetail itemDetail
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            ITEM_ATTESTATION_TYPEHASH,
            JJSKIN.AssetId.unwrap(assetId),
            ItemDetail.unwrap(itemDetail)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signSettlement(
        uint64 assetId, uint8 decision, uint8 refundReason
    ) internal view returns (bytes memory) {
        // Read tradeOfferId from purchase (needed for replay-protected signature)
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        (,,, uint48 tradeOfferId) = marketplace.purchases(aId);
        bytes32 structHash = keccak256(abi.encode(
            SETTLEMENT_TYPEHASH, assetId, tradeOfferId, decision, refundReason
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", _buildDomainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _pickSeller(uint256 seed) internal view returns (address, uint256) {
        if (seed % 2 == 0) return (seller, sellerKey);
        return (seller2, seller2Key);
    }

    function _pickBuyer(uint256 seed, address _seller) internal view returns (address) {
        if (seed % 2 == 0 && buyer != _seller) return buyer;
        if (buyer2 != _seller) return buyer2;
        return buyer; // fallback
    }

    // ========== Handler Functions ==========

    /// @notice Create listing + purchase (direct purchase path)
    function handler_purchase(uint64 assetIdSeed, uint56 priceSeed) external {
        uint56 price = uint56(bound(priceSeed, 1_000_000, 50_000_000)); // $1-$50
        uint64 assetId = _nextAssetId++;

        (address _seller, uint256 _sellerKey) = _pickSeller(assetIdSeed);
        address _buyer = _pickBuyer(assetIdSeed >> 1, _seller);

        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        bytes32 nonce = keccak256(abi.encodePacked(_nextNonce++));

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: aId,
            itemDetail: ItemDetail.wrap(0),
            price: price,
            nonce: nonce
        });

        bytes memory sig = _signListing(listing, _sellerKey);

        vm.prank(_buyer);
        try marketplace.purchaseWithSignature(listing, _seller, sig) {
            ghost_totalEscrowed += price;
            uncommittedAssets.push(assetId);
            usedNonces.push(nonce);
            usedNonceSellers.push(_seller);
            ghost_purchase_success++;
        } catch {
            ghost_purchase_fail++;
        }
    }

    /// @notice Re-list an asset that was previously refunded
    function handler_relistAfterRefund(uint56 priceSeed) external {
        if (refundedAssets.length == 0) return;

        // Pop last refunded asset
        uint64 assetId = refundedAssets[refundedAssets.length - 1];
        refundedAssets.pop();

        uint56 price = uint56(bound(priceSeed, 1_000_000, 50_000_000));
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        bytes32 nonce = keccak256(abi.encodePacked(_nextNonce++));

        (address _seller, uint256 _sellerKey) = _pickSeller(uint256(assetId));
        address _buyer = _pickBuyer(uint256(assetId) >> 1, _seller);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: aId,
            itemDetail: ItemDetail.wrap(0),
            price: price,
            nonce: nonce
        });

        bytes memory sig = _signListing(listing, _sellerKey);

        vm.prank(_buyer);
        try marketplace.purchaseWithSignature(listing, _seller, sig) {
            ghost_totalEscrowed += price;
            uncommittedAssets.push(assetId);
            ghost_relistSuccess++;
        } catch {
            // Put it back if relist failed
            refundedAssets.push(assetId);
            ghost_relistFail++;
        }
    }

    /// @notice Commit trade offer for an uncommitted purchase
    function handler_commitTradeOffer(uint256 index) external {
        if (uncommittedAssets.length == 0) return;
        index = bound(index, 0, uncommittedAssets.length - 1);

        uint64 assetId = uncommittedAssets[index];
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

        // Get seller
        (address listingSeller,,,) = marketplace.listings(aId);
        if (listingSeller == address(0)) return;

        uint64 tradeOfferId = uint64(assetId * 1000 + 1); // Unique trade offer ID

        vm.prank(listingSeller);
        try marketplace.commitTradeOffer(aId, tradeOfferId) {
            // Move from uncommitted to committed
            committedAssets.push(assetId);
            _removeFromArray(uncommittedAssets, index);
            ghost_commit_success++;
        } catch {
            ghost_commit_fail++;
        }
    }

    /// @notice Settle a committed purchase as release (seller paid)
    function handler_settle_release(uint256 index) external {
        if (committedAssets.length == 0) return;
        index = bound(index, 0, committedAssets.length - 1);

        uint64 assetId = committedAssets[index];

        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        (, uint56 price,,) = marketplace.listings(aId);

        bytes memory sig = _signSettlement(assetId, 0, 0);

        try marketplace.submitSettlement(assetId, 0, 0, sig) {
            ghost_totalEscrowed -= price;
            releasedAssets.push(assetId);
            _removeFromArray(committedAssets, index);
            ghost_settle_release_success++;
        } catch {
            ghost_settle_release_fail++;
        }
    }

    /// @notice Settle a committed purchase as refund (buyer refunded)
    function handler_settle_refund(uint256 index) external {
        if (committedAssets.length == 0) return;
        index = bound(index, 0, committedAssets.length - 1);

        uint64 assetId = committedAssets[index];

        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        (, uint56 price,,) = marketplace.listings(aId);

        uint8 reason = uint8(JJSKIN.RefundReason.Timeout);
        bytes memory sig = _signSettlement(assetId, 1, reason);

        try marketplace.submitSettlement(assetId, 1, reason, sig) {
            ghost_totalEscrowed -= price;
            refundedAssets.push(assetId);
            _removeFromArray(committedAssets, index);
            ghost_settle_refund_success++;
        } catch {
            ghost_settle_refund_fail++;
        }
    }

    /// @notice Claim timeout refund for an uncommitted purchase (uses abandonedWindow)
    function handler_claimTimeoutRefund(uint256 index) external {
        if (uncommittedAssets.length == 0) return;
        index = bound(index, 0, uncommittedAssets.length - 1);

        uint64 assetId = uncommittedAssets[index];
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

        (, uint56 price,,) = marketplace.listings(aId);

        // Warp past abandonedWindow (configurable, not hardcoded 24h)
        vm.warp(block.timestamp + marketplace.abandonedWindow() + 1);

        try marketplace.claimTimeoutRefund(aId) {
            ghost_totalEscrowed -= price;
            refundedAssets.push(assetId);
            _removeFromArray(uncommittedAssets, index);
            ghost_timeoutRefund_success++;
        } catch {
            ghost_timeoutRefund_fail++;
        }
    }

    /// @notice User withdraws accumulated balance
    function handler_withdrawBalance(uint256 userIndex) external {
        if (trackedUsers.length == 0) return;
        userIndex = bound(userIndex, 0, trackedUsers.length - 1);
        address user = trackedUsers[userIndex];

        uint256 bal = marketplace.userBalances(user);
        if (bal == 0) return;

        vm.prank(user);
        try marketplace.withdrawBalance() {} catch {}
    }

    /// @notice Create a buy order
    function handler_createBuyOrder(uint56 price, uint8 qty) external {
        price = uint56(bound(price, 1_000_000, 50_000_000));
        qty = uint8(bound(qty, 1, 5));

        uint256 totalAmount = uint256(price) * uint256(qty);

        ItemSpec spec = ItemSpecLib.encode(1, 0, 1023, 7, 0, 0);

        vm.prank(buyer);
        try marketplace.createBuyOrder(spec, price, qty) returns (JJSKIN.BuyOrderId orderId) {
            activeBuyOrders.push(orderId);
            ghost_buyOrderLocked += totalAmount;
            ghost_buyOrder_success++;
        } catch {
            ghost_buyOrder_fail++;
        }
    }

    /// @notice Cancel an active buy order
    function handler_cancelBuyOrder(uint256 index) external {
        if (activeBuyOrders.length == 0) return;
        index = bound(index, 0, activeBuyOrders.length - 1);

        JJSKIN.BuyOrderId orderId = activeBuyOrders[index];
        (address orderBuyer,, uint8 initQty,, uint56 maxPrice,, uint128 totalSpent) = marketplace.buyOrders(orderId);

        // Calculate what will be refunded to userBalance on cancel
        uint256 refundAmount = uint256(maxPrice) * uint256(initQty) - uint256(totalSpent);

        vm.prank(orderBuyer);
        try marketplace.cancelBuyOrder(orderId) {
            ghost_buyOrderLocked -= refundAmount;
            _removeFromBuyOrderArray(index);
        } catch {}
    }

    /// @notice Execute a buy order match: create listing + oracle attestation + match
    function handler_executeBuyOrderMatch(uint256 index, uint56 priceSeed) external {
        if (activeBuyOrders.length == 0) return;
        index = bound(index, 0, activeBuyOrders.length - 1);

        JJSKIN.BuyOrderId orderId = activeBuyOrders[index];
        (address orderBuyer, uint8 quantity,, JJSKIN.BuyOrderState state, uint56 maxPrice,,) = marketplace.buyOrders(orderId);
        if (state != JJSKIN.BuyOrderState.Active || quantity == 0) return;

        // Price must be <= maxPricePerItem
        uint56 price = uint56(bound(priceSeed, 1_000_000, maxPrice));

        // Use seller (never the buyer who created the order)
        address _seller = (orderBuyer != seller) ? seller : seller2;
        uint256 _sellerKey = (_seller == seller) ? sellerKey : seller2Key;

        uint64 assetId = _nextAssetId++;
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        bytes32 nonce = keccak256(abi.encodePacked(_nextNonce++));

        // ItemDetail that matches the buy order ItemSpec: paintIndex=1, defindex=7, float in range
        ItemDetail detail = ItemDetailLib.encode(1, 524288, 7, 500, 1, 0);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: aId,
            itemDetail: detail,
            price: price,
            nonce: nonce
        });

        bytes memory sellerSig = _signListing(listing, _sellerKey);
        bytes memory oracleSig = _signOracleAttestation(aId, detail);

        try marketplace.executeBuyOrderMatchWithSignature(orderId, listing, _seller, sellerSig, oracleSig) {
            // Price moves from buy order pool to escrow
            ghost_buyOrderLocked -= price;
            ghost_totalEscrowed += price;
            uncommittedAssets.push(assetId);

            // Check if order was filled (surplus refunded to buyer balance)
            (, uint8 newQty, uint8 initQty, JJSKIN.BuyOrderState newState, uint56 maxPricePerItem,, uint128 newTotalSpent) = marketplace.buyOrders(orderId);
            if (newState == JJSKIN.BuyOrderState.Filled || newQty == 0) {
                uint256 surplus = uint256(maxPricePerItem) * uint256(initQty) - uint256(newTotalSpent);
                ghost_buyOrderLocked -= surplus;
                _removeFromBuyOrderArray(index);
            }

            ghost_buyOrderMatch_success++;
        } catch {
            ghost_buyOrderMatch_fail++;
        }
    }

    // ========== Negative Handlers (must always fail) ==========

    /// @notice Attempt to purchase an asset that already has an active purchase (different nonce)
    /// Must always revert — proves "you cannot purchase a purchased listing"
    uint256 public ghost_doublePurchase_blocked;
    uint256 public ghost_doublePurchase_leaked; // Should always be 0

    function handler_attemptDoublePurchase(uint256 index) external {
        if (uncommittedAssets.length == 0 && committedAssets.length == 0) return;

        // Pick an active asset
        uint64 assetId;
        if (uncommittedAssets.length > 0) {
            index = bound(index, 0, uncommittedAssets.length - 1);
            assetId = uncommittedAssets[index];
        } else {
            index = bound(index, 0, committedAssets.length - 1);
            assetId = committedAssets[index];
        }

        // Try to purchase same assetId with a fresh nonce (different signature)
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);
        bytes32 freshNonce = keccak256(abi.encodePacked(_nextNonce++));

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: aId,
            itemDetail: ItemDetail.wrap(0),
            price: 1_000_000,
            nonce: freshNonce
        });

        bytes memory sig = _signListing(listing, seller2Key);

        vm.prank(buyer2);
        try marketplace.purchaseWithSignature(listing, seller2, sig) {
            // This should NEVER succeed
            ghost_doublePurchase_leaked++;
        } catch {
            ghost_doublePurchase_blocked++;
        }
    }

    /// @notice Attempt to purchase using a nonce that was already used
    /// Must always revert — proves "a cancelled listing cannot be purchased"
    uint256 public ghost_cancelledNonce_blocked;
    uint256 public ghost_cancelledNonce_leaked; // Should always be 0
    bytes32[] public usedNonces;
    address[] public usedNonceSellers;

    function handler_attemptCancelledNoncePurchase(uint256 index) external {
        if (usedNonces.length == 0) return;
        index = bound(index, 0, usedNonces.length - 1);

        bytes32 nonce = usedNonces[index];
        address _seller = usedNonceSellers[index];
        uint256 _sellerKey = (_seller == seller) ? sellerKey : seller2Key;

        // Use a fresh assetId but the old (cancelled) nonce
        uint64 assetId = _nextAssetId++;
        JJSKIN.AssetId aId = JJSKIN.AssetId.wrap(assetId);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: aId,
            itemDetail: ItemDetail.wrap(0),
            price: 1_000_000,
            nonce: nonce
        });

        bytes memory sig = _signListing(listing, _sellerKey);
        address _buyer = _pickBuyer(assetId, _seller);

        vm.prank(_buyer);
        try marketplace.purchaseWithSignature(listing, _seller, sig) {
            ghost_cancelledNonce_leaked++;
        } catch {
            ghost_cancelledNonce_blocked++;
        }
    }

    // ========== View Helpers ==========

    function getTrackedUsersLength() external view returns (uint256) { return trackedUsers.length; }
    function getTrackedUser(uint256 i) external view returns (address) { return trackedUsers[i]; }
    function getUncommittedLength() external view returns (uint256) { return uncommittedAssets.length; }
    function getCommittedLength() external view returns (uint256) { return committedAssets.length; }
    function getCommittedAsset(uint256 i) external view returns (uint64) { return committedAssets[i]; }
    function getUncommittedAsset(uint256 i) external view returns (uint64) { return uncommittedAssets[i]; }
    function getRefundedLength() external view returns (uint256) { return refundedAssets.length; }
    function getRefundedAsset(uint256 i) external view returns (uint64) { return refundedAssets[i]; }
    function getReleasedLength() external view returns (uint256) { return releasedAssets.length; }
    function getReleasedAsset(uint256 i) external view returns (uint64) { return releasedAssets[i]; }

    function ghost_totalCalls() external view returns (uint256) {
        return ghost_purchase_success + ghost_purchase_fail
            + ghost_commit_success + ghost_commit_fail
            + ghost_settle_release_success + ghost_settle_release_fail
            + ghost_settle_refund_success + ghost_settle_refund_fail
            + ghost_buyOrder_success + ghost_buyOrder_fail
            + ghost_buyOrderMatch_success + ghost_buyOrderMatch_fail
            + ghost_relistSuccess + ghost_relistFail
            + ghost_timeoutRefund_success + ghost_timeoutRefund_fail;
    }

    // ========== Internal ==========

    function _removeFromArray(uint64[] storage arr, uint256 index) internal {
        arr[index] = arr[arr.length - 1];
        arr.pop();
    }

    function _removeFromBuyOrderArray(uint256 index) internal {
        activeBuyOrders[index] = activeBuyOrders[activeBuyOrders.length - 1];
        activeBuyOrders.pop();
    }
}
