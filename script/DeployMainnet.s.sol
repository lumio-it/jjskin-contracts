// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {JJSKIN} from "../src/JJSKIN.sol";
import {SteamAccountFactory} from "../src/SteamAccountFactory.sol";
import {DcapAttestationVerifier} from "../src/DcapAttestationVerifier.sol";
import {IEntryPoint} from "@thirdweb-dev/contracts/prebuilts/account/interface/IEntrypoint.sol";

/// @title DeployMainnet
/// @notice Deploys full JJSKIN stack to Arbitrum One mainnet
/// @dev Usage:
///   DEPLOYER_KEY=0x... \
///   forge script script/DeployMainnet.s.sol --broadcast --rpc-url arbitrum --verify -vvv
contract DeployMainnet is Script {
    // Arbitrum One mainnet addresses (pre-existing)
    address constant USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;           // Native USDC on Arbitrum One
    address constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;    // ERC-4337 EntryPoint v0.6
    address constant AUTOMATA_DCAP = 0xaDdeC7e85c2182202b66E331f2a4A0bBB2cEEa1F;  // Automata DCAP on Arbitrum One

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);

        console.log("========================================");
        console.log("  Deploying to Arbitrum One (mainnet)");
        console.log("  Deployer:", deployer);
        console.log("========================================");

        vm.startBroadcast(deployerKey);

        // 1. Deploy SteamAccountFactory (creates Account implementation in constructor)
        SteamAccountFactory factory = new SteamAccountFactory(
            deployer,
            IEntryPoint(ENTRY_POINT)
        );

        // 2. Deploy JJSKIN marketplace
        JJSKIN marketplace = new JJSKIN(USDC, address(factory));
        marketplace.setTreasury(deployer);

        // 3. Deploy DcapAttestationVerifier
        DcapAttestationVerifier verifier = new DcapAttestationVerifier(AUTOMATA_DCAP);

        // 4. Wire verifier to marketplace
        marketplace.setAttestationVerifier(address(verifier));

        vm.stopBroadcast();

        console.log("========================================");
        console.log("  Mainnet Deployment Complete");
        console.log("========================================");
        console.log("JJSKIN               :", address(marketplace));
        console.log("STEAM_FACTORY        :", address(factory));
        console.log("DCAP_VERIFIER        :", address(verifier));
        console.log("AUTOMATA_DCAP        :", AUTOMATA_DCAP);
        console.log("USDC                 :", USDC);
        console.log("ENTRY_POINT          :", ENTRY_POINT);
        console.log("OWNER / TREASURY     :", deployer);
        console.log("========================================");
        console.log("Next steps:");
        console.log("  1. Update packages/contracts/src/addresses.ts with addresses above");
        console.log("  2. Build + push Docker image with mainnet config");
        console.log("  3. Deploy oracle CVM on Phala Cloud");
        console.log("  4. curl /attestation -> get TDX quote");
        console.log("  5. verifier.setMeasurement(keccak256(mrtd))");
        console.log("  6. marketplace.registerOracle(quote)");
        console.log("========================================");
    }
}
