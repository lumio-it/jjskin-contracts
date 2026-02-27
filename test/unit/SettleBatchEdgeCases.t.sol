// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title SubmitSettlement Edge Cases Tests
/// @notice Edge cases for EIP-712 signature verification in submitSettlement()
contract SubmitSettlementEdgeCasesTest is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    function test_submitSettlement_noCommitment() public {
        // Asset has no tradeOfferId (never had commitTradeOffer called)
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        // NOTE: No commitTradeOffer called, so tradeOfferId == 0

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(ASSET_ID);
        // Sign with tradeOfferId=0 (which is what the purchase has)
        bytes memory sig = _signSettlement(rawAssetId, 0, 0, 0);

        vm.expectRevert(JJSKIN.NoPurchaseExists.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, sig);
    }

    function test_submitSettlement_invalidSignature() public {
        // Non-oracle signer should revert
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(ASSET_ID);

        // Sign with attacker key instead of oracle key (using new typehash with tradeOfferId)
        bytes32 structHash = keccak256(abi.encode(
            keccak256("Settlement(uint64 assetId,uint48 tradeOfferId,uint8 decision,uint8 refundReason)"),
            rawAssetId, uint48(1001), uint8(0), uint8(0)
        ));
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"), keccak256("1"), block.chainid, address(marketplace)
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);
        bytes memory attackerSig = abi.encodePacked(r, s, v);

        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, attackerSig);
    }

    function test_submitSettlement_revokedOracle_reverts() public {
        // Register then revoke oracle, signature should fail
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        // Revoke oracle
        vm.prank(owner);
        marketplace.revokeOracle(oracleEOA);

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(ASSET_ID);
        bytes memory sig = _signSettlement(rawAssetId, 1001, 0, 0);

        vm.expectRevert(JJSKIN.InvalidOracleSignature.selector);
        marketplace.submitSettlement(rawAssetId, 0, 0, sig);
    }

    function test_submitSettlement_replayProtection() public {
        // Same signature can't double-settle (idempotent skip)
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        // First settlement succeeds
        _oracleClaim(ASSET_ID);

        uint256 sellerBal = marketplace.userBalances(seller);

        // Second call with same params is idempotent (silently skips)
        _oracleClaim(ASSET_ID);

        // Balance unchanged
        assertEq(marketplace.userBalances(seller), sellerBal, "Balance should not change on replay");
        assertEq(uint8(marketplace.getPurchaseStatus(ASSET_ID)), uint8(JJSKIN.PurchaseStatus.Released));
    }

    function test_submitSettlement_anyoneCanSubmit() public {
        // Anyone can submit the oracle-signed settlement, not just oracle
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 1001);

        uint64 rawAssetId = JJSKIN.AssetId.unwrap(ASSET_ID);
        bytes memory sig = _signSettlement(rawAssetId, 1001, 0, 0);

        // Submit from attacker address (not oracle) — should succeed because signature is valid
        vm.prank(attacker);
        marketplace.submitSettlement(rawAssetId, 0, 0, sig);

        assertEq(uint8(marketplace.getPurchaseStatus(ASSET_ID)), uint8(JJSKIN.PurchaseStatus.Released));
    }
}
