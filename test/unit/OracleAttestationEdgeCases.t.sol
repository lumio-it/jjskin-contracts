// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title OracleAttestationEdgeCases Tests
/// @notice Tests for oracle attestation mismatches in buy order matching
contract OracleAttestationEdgeCasesTest is BaseTest {
    JJSKIN.BuyOrderId orderId;
    ItemSpec spec;
    ItemDetail detail;

    function setUp() public override {
        super.setUp();

        // Create matching pair and a buy order
        (spec, detail) = _createMatchingItemPair();

        vm.prank(buyer);
        orderId = marketplace.createBuyOrder(spec, ITEM_PRICE, 1);
    }

    function test_oracleAttestation_wrongAssetId() public {
        // Oracle signs for asset 100, but listing uses asset 200
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8002);
        JJSKIN.AssetId wrongAssetId = JJSKIN.AssetId.wrap(9999);

        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);

        // Oracle attests for wrong assetId
        bytes memory oracleSig = _signOracleAttestationForAsset(wrongAssetId, detail);

        vm.expectRevert(JJSKIN.InvalidOracleAttestation.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    function test_oracleAttestation_wrongItemDetail() public {
        // Oracle signs for different itemDetail than what listing has
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(8003);
        JJSKIN.ListingData memory listing = _createListingDataWithDetail(assetId, seller, ITEM_PRICE, detail);
        bytes memory sellerSig = _signListing(listing, sellerKey);

        // Create a different ItemDetail (different paintIndex)
        ItemDetail wrongDetail = ItemDetailLib.encode(
            2,       // paintIndex=2 (different from detail which has paintIndex=1)
            524288,
            7,
            500,
            1,
            0
        );

        bytes memory oracleSig = _signOracleAttestationForAsset(assetId, wrongDetail);

        vm.expectRevert(JJSKIN.InvalidOracleAttestation.selector);
        marketplace.executeBuyOrderMatchWithSignature(orderId, listing, seller, sellerSig, oracleSig);
    }

    // ========== Helpers ==========

    /// @notice Sign oracle attestation with specific assetId and itemDetail
    function _signOracleAttestationForAsset(
        JJSKIN.AssetId assetId,
        ItemDetail _detail
    ) internal view returns (bytes memory) {
        bytes32 ATTESTATION_TYPEHASH = keccak256(
            "ItemAttestation(uint64 assetId,uint64 itemDetail)"
        );

        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH,
            JJSKIN.AssetId.unwrap(assetId),
            ItemDetail.unwrap(_detail)
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
}
