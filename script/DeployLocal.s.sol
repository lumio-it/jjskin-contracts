// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {JJSKIN, ItemDetail} from "../src/JJSKIN.sol";
import "../src/mocks/MockUSDC.sol";
import "../test/base/BaseTest.sol"; // MockSteamAccountFactory, MockAttestationVerifier
import "../test/mocks/MockSmartAccount.sol";

/// @title DeployLocal
/// @notice Deploys full JJSKIN marketplace to Anvil with a ready-to-settle purchase
/// @dev Usage:
///   anvil &
///   DEPLOYER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
///   ORACLE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
///   SELLER_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
///   SELLER_STEAM_ID=76561198366018280 \
///   BUYER_STEAM_ID=76561198404282737 \
///   ASSET_ID=40964044588 \
///   TRADE_OFFER_ID=8653813160 \
///   PRICE_USDC=10000000 \
///   forge script script/DeployLocal.s.sol --broadcast --rpc-url http://localhost:8545
contract DeployLocal is Script {
    bytes32 private constant LISTING_TYPEHASH = keccak256(
        "ListingData(uint64 assetId,uint64 itemDetail,uint56 price,bytes32 nonce)"
    );

    function run() external {
        // ── Read env ──
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        uint256 oracleKey  = vm.envUint("ORACLE_KEY");
        uint256 sellerKey  = vm.envUint("SELLER_KEY");

        uint64 sellerSteamId = uint64(vm.envUint("SELLER_STEAM_ID"));
        uint64 buyerSteamId  = uint64(vm.envUint("BUYER_STEAM_ID"));
        uint64 assetId       = uint64(vm.envUint("ASSET_ID"));
        uint64 tradeOfferId  = uint64(vm.envUint("TRADE_OFFER_ID"));
        uint56 price         = uint56(vm.envUint("PRICE_USDC"));

        address oracleEOA  = vm.addr(oracleKey);
        address sellerEOA  = vm.addr(sellerKey);
        address deployerEOA = vm.addr(deployerKey);

        // ═══════════════════════════════════════════════════════
        // Phase 1: Deploy infrastructure (deployer = owner = buyer)
        // ═══════════════════════════════════════════════════════
        vm.startBroadcast(deployerKey);

        // 1. Deploy mock tokens & infrastructure
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        MockAttestationVerifier verifier = new MockAttestationVerifier();

        // 2. Deploy marketplace
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));
        marketplace.setTreasury(deployerEOA);
        marketplace.setAttestationVerifier(address(verifier));
        marketplace.registerOracle(abi.encode(oracleEOA));

        // 3. Deploy seller smart account (needed for ERC-1271 sig verification)
        MockSmartAccount sellerAccount = new MockSmartAccount(sellerEOA);

        // 4. Register users in factory
        //    - Seller = smart account address (for ERC-1271)
        //    - Buyer = deployer EOA directly (no smart account needed)
        factory.registerForTesting(address(sellerAccount), sellerSteamId);
        factory.registerForTesting(deployerEOA, buyerSteamId);

        // 5. Fund buyer (deployer) with USDC & approve marketplace
        usdc.mint(deployerEOA, 1_000_000_000); // 1000 USDC
        usdc.approve(address(marketplace), type(uint256).max);

        // 6. Create listing signature (EIP-712 signed by seller EOA)
        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: JJSKIN.AssetId.wrap(assetId),
            itemDetail: ItemDetail.wrap(0),
            price: price,
            nonce: keccak256(abi.encodePacked(sellerSteamId, assetId))
        });
        bytes memory sig = _signListing(listing, sellerKey, address(marketplace));

        // 7. Purchase (deployer = buyer = msg.sender, registered in factory)
        marketplace.purchaseWithSignature(listing, address(sellerAccount), sig);

        vm.stopBroadcast();

        // ═══════════════════════════════════════════════════════
        // Phase 2: Commit trade offer (must come FROM seller smart account)
        // ═══════════════════════════════════════════════════════
        vm.startBroadcast(sellerKey);

        sellerAccount.execute(
            address(marketplace),
            abi.encodeCall(JJSKIN.commitTradeOffer, (JJSKIN.AssetId.wrap(assetId), tradeOfferId))
        );

        vm.stopBroadcast();

        // ═══════════════════════════════════════════════════════
        // Print deployed addresses for config
        // ═══════════════════════════════════════════════════════
        console.log("========================================");
        console.log("  Local E2E Deployment Complete");
        console.log("========================================");
        console.log("MARKETPLACE      :", address(marketplace));
        console.log("USDC             :", address(usdc));
        console.log("FACTORY          :", address(factory));
        console.log("VERIFIER         :", address(verifier));
        console.log("SELLER_ACCOUNT   :", address(sellerAccount));
        console.log("BUYER (deployer) :", deployerEOA);
        console.log("ORACLE_EOA       :", oracleEOA);
        console.log("ASSET_ID         :", assetId);
        console.log("TRADE_OFFER_ID   :", tradeOfferId);
        console.log("PRICE_USDC       :", price);
        console.log("========================================");
        console.log("Update local-oracle.yaml with:");
        console.log("  contract_address:", address(marketplace));
        console.log("========================================");
    }

    function _signListing(
        JJSKIN.ListingData memory listing,
        uint256 privateKey,
        address marketplaceAddr
    ) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));

        bytes32 domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("JJSKIN"),
            keccak256("1"),
            block.chainid,
            marketplaceAddr
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
