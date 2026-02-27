// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, console2} from "forge-std/Test.sol";
import {JJSKIN, ItemDetail} from "../src/JJSKIN.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockSmartAccount} from "./mocks/MockSmartAccount.sol";
import {SteamAccountFactory} from "../src/SteamAccountFactory.sol";
import {IEntryPoint} from "@thirdweb-dev/contracts/prebuilts/account/interface/IEntrypoint.sol";

contract CommitTradeOfferGasTest is Test {
    JJSKIN public marketplace;
    MockUSDC public usdc;
    SteamAccountFactory public factory;

    uint256 public ownerKey = 0x1;
    uint256 public oracleKey = 0x2;
    uint256 public sellerKey = 0x3;
    uint256 public buyerKey = 0x4;

    address public ownerEOA = vm.addr(ownerKey);
    address public oracleEOA = vm.addr(oracleKey);
    address public sellerEOA = vm.addr(sellerKey);
    address public buyerEOA = vm.addr(buyerKey);

    address public oracle;
    address public owner;
    address public seller;
    address public buyer;

    uint256 constant PRICE = 100 * 1e6; // 100 USDC
    uint256 constant STEAM_ID_SELLER = 76561198000000001;
    uint256 constant STEAM_ID_BUYER = 76561198000000002;

    bytes32 private constant LISTING_TYPEHASH = keccak256(
        "ListingData(uint64 assetId,uint64 itemDetail,uint56 price,bytes32 nonce)"
    );

    function setUp() public {
        // Deploy smart accounts
        oracle = address(new MockSmartAccount(oracleEOA));
        owner = address(new MockSmartAccount(ownerEOA));
        seller = address(new MockSmartAccount(sellerEOA));
        buyer = address(new MockSmartAccount(buyerEOA));

        // Deploy mocks
        usdc = new MockUSDC();

        // Deploy factory
        IEntryPoint entryPoint = IEntryPoint(makeAddr("entryPoint"));
        factory = new SteamAccountFactory(
            makeAddr("deployer"),
            entryPoint
        );

        vm.prank(owner);
        marketplace = new JJSKIN(
            address(usdc),
            address(factory)
        );

        // Set treasury
        vm.prank(owner);
        marketplace.setTreasury(oracle);

        // Mock factory.isRegistered to return true for our test accounts
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

        // Fund buyer with USDC
        usdc.mint(buyer, 1000 * 1e6);

        vm.prank(buyer);
        usdc.approve(address(marketplace), type(uint256).max);
    }

    function _signListing(JJSKIN.ListingData memory listing, uint256 privateKey) internal view returns (bytes memory) {
        // Calculate domain separator matching JJSKIN.sol constructor
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("JJSKIN"),
                keccak256("1"),
                block.chainid,
                address(marketplace)
            )
        );
        bytes32 structHash = keccak256(abi.encode(
            LISTING_TYPEHASH,
            listing.assetId,
            listing.itemDetail,
            listing.price,
            listing.nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_CommitTradeOffer_GasCost() public {
        // Create listing
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(40698064729);
        ItemDetail itemDetail = ItemDetail.wrap(0);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });

        bytes memory signature = _signListing(listing, sellerKey);

        // Buyer purchases
        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);

        // Seller commits trade offer
        uint64 tradeOfferId = 7865432109; // Example Steam trade offer ID (uint64)

        uint256 gasBefore = gasleft();
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, tradeOfferId);
        uint256 gasUsed = gasBefore - gasleft();

        console2.log("=== commitTradeOffer Gas Cost (ULTRA OPTIMIZED) ===");
        console2.log("Gas used:", gasUsed);
        console2.log("At 0.1 gwei, cost:", gasUsed * 1e8 / 1e18, "ETH");
        console2.log("At $3000/ETH:", gasUsed * 1e8 * 3000 / 1e18, "USD (x1e6)");

        // Verify commitment stored in Purchase struct
        uint48 storedTradeOffer = marketplace.getTradeOfferCommitment(JJSKIN.AssetId.unwrap(assetId));
        assertEq(storedTradeOffer, tradeOfferId, "Trade offer not stored correctly");

        // Note: No reverse mapping needed - zkVM verifies actual items via TLSNotary proof
    }

    function test_CommitTradeOffer_ViewFunctions_GasCost() public {
        // Setup - create purchase and commit
        JJSKIN.AssetId assetId = JJSKIN.AssetId.wrap(40698064729);
        ItemDetail itemDetail = ItemDetail.wrap(0);

        JJSKIN.ListingData memory listing = JJSKIN.ListingData({
            assetId: assetId,
            itemDetail: itemDetail,
            price: uint56(PRICE),
            nonce: keccak256(abi.encode(block.timestamp, seller, assetId))
        });

        bytes memory signature = _signListing(listing, sellerKey);

        vm.prank(buyer);
        marketplace.purchaseWithSignature(listing, seller, signature);

        uint64 tradeOfferId = 7865432109;
        vm.prank(seller);
        marketplace.commitTradeOffer(assetId, tradeOfferId);

        // Test view function gas
        uint256 gasBefore = gasleft();
        marketplace.getTradeOfferCommitment(JJSKIN.AssetId.unwrap(assetId));
        uint256 gasView1 = gasBefore - gasleft();

        gasBefore = gasleft();
        marketplace.isCommitmentDeadlinePassed(JJSKIN.AssetId.unwrap(assetId));
        uint256 gasView2 = gasBefore - gasleft();

        console2.log("=== View Function Gas Costs ===");
        console2.log("getTradeOfferCommitment():", gasView1);
        console2.log("isCommitmentDeadlinePassed():", gasView2);
    }
}
