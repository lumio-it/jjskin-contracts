// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {JJSKIN} from "../src/JJSKIN.sol";

/// @title SettleLocal
/// @notice Generate EIP-712 settlement signature + submit to Anvil
/// @dev Usage:
///   MARKETPLACE=0x... ASSET_ID=40964044588 DECISION=0 REFUND_REASON=0 \
///   ORACLE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
///   forge script script/SettleLocal.s.sol --broadcast --rpc-url http://localhost:8545 -vvv
contract SettleLocal is Script {
    bytes32 private constant SETTLEMENT_TYPEHASH = keccak256(
        "Settlement(uint64 assetId,uint8 decision,uint8 refundReason)"
    );

    function run() external {
        address marketplace = vm.envAddress("MARKETPLACE");
        uint64 assetId      = uint64(vm.envUint("ASSET_ID"));
        uint8 decision      = uint8(vm.envUint("DECISION"));
        uint8 refundReason  = uint8(vm.envUint("REFUND_REASON"));
        uint256 oracleKey   = vm.envUint("ORACLE_KEY");

        // ── Build EIP-712 signature (same as signer.rs) ──
        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"),
            keccak256("1"),
            block.chainid,
            marketplace
        ));

        bytes32 structHash = keccak256(abi.encode(
            SETTLEMENT_TYPEHASH, assetId, decision, refundReason
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(oracleKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        console.log("========================================");
        console.log("  EIP-712 Settlement Signature");
        console.log("========================================");
        console.log("Oracle     :", vm.addr(oracleKey));
        console.log("Asset ID   :", assetId);
        console.log("Decision   :", decision == 0 ? "Release" : "Refund");
        console.log("Refund Code:", refundReason);
        console.log("Signature  :");
        console.logBytes(signature);

        // ── Check pre-state ──
        JJSKIN jjskin = JJSKIN(marketplace);
        (address buyer, uint40 purchaseTime, JJSKIN.PurchaseStatus status, uint48 tradeOfferId) = jjskin.purchases(JJSKIN.AssetId.wrap(assetId));
        console.log("========================================");
        console.log("  Pre-Settlement State");
        console.log("========================================");
        console.log("Buyer      :", buyer);
        console.log("Status     :", uint8(status)); // 0=Active, 1=Released, 2=Refunded
        console.log("TradeOffer :", tradeOfferId);

        if (status != JJSKIN.PurchaseStatus.Active) {
            console.log("Already settled! Skipping.");
            return;
        }

        // ── Submit settlement ──
        vm.startBroadcast(oracleKey);
        jjskin.submitSettlement(assetId, decision, refundReason, signature);
        vm.stopBroadcast();

        // ── Verify post-state ──
        (, , JJSKIN.PurchaseStatus postStatus, ) = jjskin.purchases(JJSKIN.AssetId.wrap(assetId));
        console.log("========================================");
        console.log("  Post-Settlement State");
        console.log("========================================");
        console.log("Status     :", uint8(postStatus)); // 1=Released, 2=Refunded
        console.log(postStatus == JJSKIN.PurchaseStatus.Released ? "RELEASED - Seller paid!" : "REFUNDED - Buyer refunded!");
        console.log("========================================");
    }
}
