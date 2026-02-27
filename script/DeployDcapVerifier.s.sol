// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Script.sol";
import {DcapAttestationVerifier} from "../src/DcapAttestationVerifier.sol";
import {JJSKIN} from "../src/JJSKIN.sol";

/// @title DeployDcapVerifier
/// @notice Deploys DcapAttestationVerifier on Arbitrum and wires it to JJSKIN
/// @dev Usage (testnet):
///   DEPLOYER_KEY=0x... \
///   JJSKIN_ADDRESS=0xFfA4F5972b66292549Ec85388ef7171F0751360B \
///   AUTOMATA_DCAP=0x95175096a9B74165BE0ac84260cc14Fc1c0EF5FF \
///   forge script script/DeployDcapVerifier.s.sol --broadcast --rpc-url arb_sepolia -vvv
///
///   Usage (mainnet):
///   DEPLOYER_KEY=0x... \
///   JJSKIN_ADDRESS=0x... \
///   AUTOMATA_DCAP=0xaDdeC7e85c2182202b66E331f2a4A0bBB2cEEa1F \
///   forge script script/DeployDcapVerifier.s.sol --broadcast --rpc-url arb_mainnet --verify
contract DeployDcapVerifier is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_KEY");
        address jjskinAddr = vm.envAddress("JJSKIN_ADDRESS");
        address automataDcap = vm.envAddress("AUTOMATA_DCAP");

        vm.startBroadcast(deployerKey);

        // 1. Deploy the DCAP verifier
        DcapAttestationVerifier verifier = new DcapAttestationVerifier(automataDcap);
        console.log("DcapAttestationVerifier deployed:", address(verifier));

        // 2. Set initial active measurement if provided
        bytes32 mrEnclave = vm.envOr("MRENCLAVE", bytes32(0));
        if (mrEnclave != bytes32(0)) {
            verifier.setMeasurement(mrEnclave);
            console.log("Active mrEnclave set:");
            console.logBytes32(mrEnclave);
        }

        // 3. Set verifier on JJSKIN marketplace
        JJSKIN marketplace = JJSKIN(jjskinAddr);
        marketplace.setAttestationVerifier(address(verifier));
        console.log("AttestationVerifier set on JJSKIN:", jjskinAddr);

        vm.stopBroadcast();

        console.log("========================================");
        console.log("  DCAP Verifier Deployment Complete");
        console.log("========================================");
        console.log("VERIFIER     :", address(verifier));
        console.log("AUTOMATA_DCAP:", automataDcap);
        console.log("JJSKIN       :", jjskinAddr);
        console.log("========================================");
        console.log("Next steps:");
        console.log("  1. Build SGX image -> note MRENCLAVE");
        console.log("  2. verifier.setMeasurement(mrEnclave)");
        console.log("  3. Deploy server on Azure DCsv3");
        console.log("  4. curl /attestation -> registerOracle(quote)");
        console.log("========================================");
    }
}
