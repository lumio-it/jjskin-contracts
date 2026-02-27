// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {JJSKIN} from "../src/JJSKIN.sol";
import {DcapAttestationVerifier} from "../src/DcapAttestationVerifier.sol";

/// @title DeployTestnet
/// @notice Deploys JJSKIN + DcapAttestationVerifier to Arbitrum Sepolia
/// @dev Usage:
///   DEPLOYER_KEY=0x... \
///   forge script script/DeployTestnet.s.sol --broadcast --rpc-url arbitrum-sepolia -vvv
contract DeployTestnet is Script {
    // Existing contracts on Arbitrum Sepolia (reused)
    address constant USDC = 0x15Fc0329b044fC082272031D30c286B46ce68203;
    address constant STEAM_FACTORY = 0x627f747eb08442d0A61fC65093f21210142d013f;
    // Automata DCAP AttestationFee on Arbitrum Sepolia
    address constant AUTOMATA_DCAP = 0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address deployer = vm.addr(deployerKey);

        vm.startBroadcast(deployerKey);

        // 1. Deploy JJSKIN marketplace
        JJSKIN marketplace = new JJSKIN(USDC, STEAM_FACTORY);
        marketplace.setTreasury(deployer);

        // 2. Deploy DcapAttestationVerifier
        DcapAttestationVerifier verifier = new DcapAttestationVerifier(AUTOMATA_DCAP);

        // 3. Wire verifier to marketplace
        marketplace.setAttestationVerifier(address(verifier));

        vm.stopBroadcast();

        console.log("========================================");
        console.log("  Testnet Deployment Complete");
        console.log("========================================");
        console.log("JJSKIN           :", address(marketplace));
        console.log("DCAP_VERIFIER    :", address(verifier));
        console.log("AUTOMATA_DCAP    :", AUTOMATA_DCAP);
        console.log("USDC             :", USDC);
        console.log("STEAM_FACTORY    :", STEAM_FACTORY);
        console.log("OWNER / TREASURY :", deployer);
        console.log("========================================");
        console.log("Next steps:");
        console.log("  1. Update packages/contracts/src/addresses.ts");
        console.log("  2. Build SGX image -> note MRENCLAVE");
        console.log("  3. verifier.setMeasurement(mrEnclave)");
        console.log("  4. Deploy TEE server on Azure DCsv3");
        console.log("  5. curl /attestation -> registerOracle(quote)");
        console.log("========================================");
    }
}
