// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/**
 * @title IJJSKIN
 * @notice Interface for the JJSKIN escrow contract
 * @dev Oracle-signs-user-submits settlement via EIP-712
 */
interface IJJSKIN {
    /// @notice Purchase status enum (must match JJSKIN.PurchaseStatus)
    enum PurchaseStatus {
        Active,     // Trade in progress, funds escrowed
        Released,   // Oracle verified, seller paid
        Refunded    // Refund processed, buyer paid back
    }

    /// @notice Refund reason enum (must match JJSKIN.RefundReason)
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
        TradeRollback,      // 14 - GetTradeStatus status 12 (check off-chain)
        DeprecatedRollback, // 15 - GetTradeStatus deprecated rollback states
        TradeNotExist       // 16 - SteamCommunity "does not exist" (seller's fault)
    }

    /// @notice Get purchase status for an asset
    /// @dev Reverts if no purchase exists
    function getPurchaseStatus(uint64 assetId) external view returns (PurchaseStatus);

    /// @notice Submit a settlement with oracle EIP-712 signature
    /// @param assetId The Steam asset ID
    /// @param decision 0 = release, 1 = refund
    /// @param refundReason RefundReason enum value (0 if release)
    /// @param oracleSignature EIP-712 signature from a registered oracle
    function submitSettlement(uint64 assetId, uint8 decision, uint8 refundReason, bytes calldata oracleSignature) external;

    /// @notice Check if a purchase exists and is active
    function isPurchaseActive(uint64 assetId) external view returns (bool);

    /// @notice Get batch asset information for multiple assets
    function getBatchAssetInfo(uint64[] calldata assetIds)
        external
        view
        returns (
            uint56[] memory prices,
            uint40[] memory purchaseTimes,
            PurchaseStatus[] memory statuses,
            bool[] memory exists
        );

    /// @notice Get the delivery window (time seller has to send trade)
    function deliveryWindow() external view returns (uint256);

    /// @notice Get the seller address for a listing
    function getSellerAddress(uint64 assetId) external view returns (address seller);

    /// @notice Check if an address is a registered oracle
    function oracles(address oracle) external view returns (bool);

    /// @notice Set the attestation verifier contract (owner only)
    function setAttestationVerifier(address _verifier) external;

    /// @notice Register oracle via TEE attestation
    function registerOracle(bytes calldata attestation) external;
}
