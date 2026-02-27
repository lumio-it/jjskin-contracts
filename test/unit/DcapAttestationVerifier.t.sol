// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "forge-std/Test.sol";
import {DcapAttestationVerifier, IAutomataDcapAttestation} from "../../src/DcapAttestationVerifier.sol";
import {JJSKIN} from "../../src/JJSKIN.sol";
import "../../src/mocks/MockUSDC.sol";
import "../../test/base/BaseTest.sol"; // MockSteamAccountFactory

/// @notice Mock Automata DCAP contract that always succeeds
contract MockDcapSuccess is IAutomataDcapAttestation {
    function verifyAndAttestOnChain(bytes calldata)
        external
        pure
        returns (bool, bytes memory)
    {
        return (true, "");
    }
}

/// @notice Mock Automata DCAP contract that always fails
contract MockDcapFailure is IAutomataDcapAttestation {
    function verifyAndAttestOnChain(bytes calldata)
        external
        pure
        returns (bool, bytes memory)
    {
        return (false, "");
    }
}

contract DcapAttestationVerifierTest is Test {
    DcapAttestationVerifier public verifier;
    MockDcapSuccess public mockDcap;
    MockDcapFailure public mockDcapFail;

    address public owner = address(this);
    bytes32 public constant TEST_MRENCLAVE = bytes32(uint256(0xdeadbeef));
    address public constant ORACLE_ADDR = address(0x1234567890AbcdEF1234567890aBcdef12345678);

    // TDX test data: 48-byte MRTD split into bytes32 + bytes16
    bytes32 public constant TEST_MRTD_PART1 = bytes32(uint256(0xAAAABBBBCCCCDDDD));
    bytes16 public constant TEST_MRTD_PART2 = bytes16(uint128(0xEEEEFFFF00001111));
    bytes32 public testMrtdHash;

    // RTMR[3] test data: 48-byte RTMR3 split into bytes32 + bytes16
    bytes32 public constant TEST_RTMR3_PART1 = bytes32(uint256(0x11112222333344445555666677778888));
    bytes16 public constant TEST_RTMR3_PART2 = bytes16(uint128(0x9999AAAABBBBCCCC));
    bytes32 public testRtmr3Hash;

    // keccak256 of 48 zero bytes — used for TDX tests that don't set explicit RTMR3
    bytes32 public zeroRtmr3Hash;

    function setUp() public {
        mockDcap = new MockDcapSuccess();
        mockDcapFail = new MockDcapFailure();
        verifier = new DcapAttestationVerifier(address(mockDcap));

        // Compute keccak256 of the 48-byte MRTD
        testMrtdHash = keccak256(abi.encodePacked(TEST_MRTD_PART1, TEST_MRTD_PART2));

        // Compute keccak256 of the 48-byte RTMR3 test data
        testRtmr3Hash = keccak256(abi.encodePacked(TEST_RTMR3_PART1, TEST_RTMR3_PART2));

        // keccak256 of 48 zero bytes (default RTMR3 in quotes built by _buildTdxQuote)
        zeroRtmr3Hash = keccak256(new bytes(48));
    }

    /// @dev Build a minimal valid SGX quote with the given mrEnclave and oracle address in reportData
    function _buildQuote(bytes32 mrEnclave, address oracleAddr) internal pure returns (bytes memory) {
        // Quote = 48 byte header + 384 byte report body + 4 byte sig len = 436 bytes min
        bytes memory quote = new bytes(436);

        // Write mrEnclave at offset 112 (48 header + 64 in body)
        assembly {
            mstore(add(add(quote, 32), 112), mrEnclave)
        }

        // Write oracle address at offset 368 (48 header + 320 in body)
        // address is 20 bytes, stored left-aligned in reportData
        bytes20 addrBytes = bytes20(oracleAddr);
        assembly {
            mstore(add(add(quote, 32), 368), addrBytes)
        }

        return quote;
    }

    /// @dev Build a minimal valid TDX quote with the given MRTD and oracle address in reportData
    function _buildTdxQuote(bytes32 mrtdPart1, bytes16 mrtdPart2, address oracleAddr)
        internal
        pure
        returns (bytes memory)
    {
        // Quote = 48 byte header + 584 byte TD report body + 4 byte sig len = 636 bytes min
        bytes memory quote = new bytes(636);

        // Set TEE type to TDX (bytes 4-7 = 0x81000000)
        quote[4] = 0x81;

        // Write MRTD at offset 184 (48 header + 136 in body), 48 bytes = 32 + 16
        assembly {
            let base := add(quote, 32)
            mstore(add(base, 184), mrtdPart1)
            // mstore writes 32 bytes; only first 16 bytes of mrtdPart2 matter
            mstore(add(base, 216), mrtdPart2)
        }

        // Write oracle address at offset 568 (48 header + 520 in body)
        bytes20 addrBytes = bytes20(oracleAddr);
        assembly {
            mstore(add(add(quote, 32), 568), addrBytes)
        }

        return quote;
    }

    /// @dev Build a TDX quote with explicit RTMR[3] data (48 bytes = bytes32 + bytes16)
    function _buildTdxQuoteWithRtmr3(
        bytes32 mrtdPart1,
        bytes16 mrtdPart2,
        bytes32 rtmr3Part1,
        bytes16 rtmr3Part2,
        address oracleAddr
    ) internal pure returns (bytes memory) {
        bytes memory quote = new bytes(636);

        // Set TEE type to TDX (bytes 4-7 = 0x81000000)
        quote[4] = 0x81;

        // Write MRTD at offset 184 (48 header + 136 in body)
        assembly {
            let base := add(quote, 32)
            mstore(add(base, 184), mrtdPart1)
            mstore(add(base, 216), mrtdPart2)
        }

        // Write RTMR[3] at offset 520 (48 header + 472 in body)
        assembly {
            let base := add(quote, 32)
            mstore(add(base, 520), rtmr3Part1)
            mstore(add(base, 552), rtmr3Part2)
        }

        // Write oracle address at offset 568 (48 header + 520 in body)
        bytes20 addrBytes = bytes20(oracleAddr);
        assembly {
            mstore(add(add(quote, 32), 568), addrBytes)
        }

        return quote;
    }

    // ========== Deployment Tests ==========

    function test_constructor_setsImmutables() public view {
        assertEq(address(verifier.dcapAttestation()), address(mockDcap));
        assertEq(verifier.owner(), owner);
        assertEq(verifier.activeMeasurement(), bytes32(0));
    }

    // ========== Measurement Management ==========

    function test_setMeasurement() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        assertEq(verifier.activeMeasurement(), TEST_MRENCLAVE);
    }

    function test_setMeasurement_replacesOld() public {
        bytes32 oldMr = bytes32(uint256(1));
        bytes32 newMr = bytes32(uint256(2));

        verifier.setMeasurement(oldMr);
        assertEq(verifier.activeMeasurement(), oldMr);

        verifier.setMeasurement(newMr);
        assertEq(verifier.activeMeasurement(), newMr);
    }

    function test_setMeasurement_clearToZero() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        verifier.setMeasurement(bytes32(0));
        assertEq(verifier.activeMeasurement(), bytes32(0));
    }

    function test_setMeasurement_onlyOwner() public {
        vm.prank(address(0xbad));
        vm.expectRevert();
        verifier.setMeasurement(TEST_MRENCLAVE);
    }

    function test_setMeasurement_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit DcapAttestationVerifier.MeasurementSet(TEST_MRENCLAVE, bytes32(0));
        verifier.setMeasurement(TEST_MRENCLAVE);
    }

    function test_setMeasurement_emitsOldValue() public {
        bytes32 oldMr = bytes32(uint256(1));
        bytes32 newMr = bytes32(uint256(2));
        verifier.setMeasurement(oldMr);

        vm.expectEmit(true, true, false, false);
        emit DcapAttestationVerifier.MeasurementSet(newMr, oldMr);
        verifier.setMeasurement(newMr);
    }

    // ========== SGX Verification Tests ==========

    function test_verifyAttestation_sgx_success() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);

        address result = verifier.verifyAttestation(quote);
        assertEq(result, ORACLE_ADDR);
    }

    function test_verifyAttestation_noActiveMeasurement() public {
        // activeMeasurement is bytes32(0) — not set
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);

        vm.expectRevert(DcapAttestationVerifier.NoActiveMeasurement.selector);
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_dcapFails() public {
        DcapAttestationVerifier failVerifier = new DcapAttestationVerifier(address(mockDcapFail));
        failVerifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);

        vm.expectRevert(DcapAttestationVerifier.DcapVerificationFailed.selector);
        failVerifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_wrongMeasurement() public {
        bytes32 activeMr = bytes32(uint256(1));
        bytes32 quoteMr = bytes32(uint256(2));
        verifier.setMeasurement(activeMr);

        bytes memory quote = _buildQuote(quoteMr, ORACLE_ADDR);

        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.MeasurementNotActive.selector,
                quoteMr
            )
        );
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_oldBuildBlockedAfterRotation() public {
        bytes32 oldMr = bytes32(uint256(1));
        bytes32 newMr = bytes32(uint256(2));

        // Set old measurement, verify it works
        verifier.setMeasurement(oldMr);
        bytes memory oldQuote = _buildQuote(oldMr, ORACLE_ADDR);
        assertEq(verifier.verifyAttestation(oldQuote), ORACLE_ADDR);

        // Rotate to new measurement
        verifier.setMeasurement(newMr);

        // Old build can no longer register (different quote to avoid replay check)
        address otherAddr = address(0xAAAA);
        bytes memory oldQuote2 = _buildQuote(oldMr, otherAddr);
        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.MeasurementNotActive.selector, oldMr)
        );
        verifier.verifyAttestation(oldQuote2);

        // New build works
        bytes memory newQuote = _buildQuote(newMr, ORACLE_ADDR);
        assertEq(verifier.verifyAttestation(newQuote), ORACLE_ADDR);
    }

    function test_verifyAttestation_quoteTooShort() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory shortQuote = new bytes(47); // shorter than header

        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.QuoteTooShort.selector, 47)
        );
        verifier.verifyAttestation(shortQuote);
    }

    function test_verifyAttestation_sgx_quoteTooShort() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        // SGX header (TEE type = 0) but too short for SGX body
        bytes memory shortQuote = new bytes(431); // 1 byte short of SGX min (432)

        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.QuoteTooShort.selector, 431)
        );
        verifier.verifyAttestation(shortQuote);
    }

    function test_verifyAttestation_zeroAddressInReportData() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, address(0));

        vm.expectRevert(DcapAttestationVerifier.ZeroAddressInReportData.selector);
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_differentAddresses() public {
        verifier.setMeasurement(TEST_MRENCLAVE);

        address addr1 = address(0x1111111111111111111111111111111111111111);
        address addr2 = address(0x2222222222222222222222222222222222222222);

        assertEq(verifier.verifyAttestation(_buildQuote(TEST_MRENCLAVE, addr1)), addr1);
        assertEq(verifier.verifyAttestation(_buildQuote(TEST_MRENCLAVE, addr2)), addr2);
    }

    // ========== TDX Verification Tests ==========

    function test_verifyAttestation_tdx_success() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);

        address result = verifier.verifyAttestation(quote);
        assertEq(result, ORACLE_ADDR);
    }

    function test_verifyAttestation_tdx_wrongMeasurement() public {
        // Set a different measurement than what's in the quote
        verifier.setMeasurement(bytes32(uint256(0x999)));
        verifier.setRtmr3(zeroRtmr3Hash);

        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);

        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.MeasurementNotActive.selector,
                testMrtdHash
            )
        );
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_tdx_quoteTooShort() public {
        verifier.setMeasurement(testMrtdHash);

        // TDX header (TEE type = 0x81) but too short for TDX body
        bytes memory shortQuote = new bytes(631); // 1 byte short of TDX min (632)
        shortQuote[4] = 0x81;

        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.QuoteTooShort.selector, 631)
        );
        verifier.verifyAttestation(shortQuote);
    }

    function test_verifyAttestation_tdx_zeroAddress() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, address(0));

        vm.expectRevert(DcapAttestationVerifier.ZeroAddressInReportData.selector);
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_tdx_differentAddresses() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);

        address addr1 = address(0x1111111111111111111111111111111111111111);
        address addr2 = address(0x2222222222222222222222222222222222222222);

        assertEq(
            verifier.verifyAttestation(
                _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, addr1)
            ),
            addr1
        );
        assertEq(
            verifier.verifyAttestation(
                _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, addr2)
            ),
            addr2
        );
    }

    function test_verifyAttestation_tdx_differentMrtd() public {
        verifier.setRtmr3(zeroRtmr3Hash);

        // Use different MRTD values
        bytes32 mrtdA1 = bytes32(uint256(0x1111));
        bytes16 mrtdA2 = bytes16(uint128(0x2222));
        bytes32 hashA = keccak256(abi.encodePacked(mrtdA1, mrtdA2));

        bytes32 mrtdB1 = bytes32(uint256(0x3333));
        bytes16 mrtdB2 = bytes16(uint128(0x4444));
        bytes32 hashB = keccak256(abi.encodePacked(mrtdB1, mrtdB2));

        // Set measurement A, verify A works
        verifier.setMeasurement(hashA);
        assertEq(
            verifier.verifyAttestation(_buildTdxQuote(mrtdA1, mrtdA2, ORACLE_ADDR)),
            ORACLE_ADDR
        );

        // Rotate to measurement B
        verifier.setMeasurement(hashB);

        // A no longer works
        address otherAddr = address(0xBBBB);
        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.MeasurementNotActive.selector, hashA)
        );
        verifier.verifyAttestation(_buildTdxQuote(mrtdA1, mrtdA2, otherAddr));

        // B works
        assertEq(
            verifier.verifyAttestation(_buildTdxQuote(mrtdB1, mrtdB2, ORACLE_ADDR)),
            ORACLE_ADDR
        );
    }

    // ========== TEE Type Detection Tests ==========

    function test_verifyAttestation_unsupportedTeeType() public {
        verifier.setMeasurement(TEST_MRENCLAVE);

        // Create a quote with an unknown TEE type (0xFF at byte 4)
        bytes memory quote = new bytes(636);
        quote[4] = 0xFF;

        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.UnsupportedTeeType.selector,
                bytes4(0xFF000000)
            )
        );
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_sgxToTdxMigration() public {
        // Phase 1: SGX oracle
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory sgxQuote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);
        assertEq(verifier.verifyAttestation(sgxQuote), ORACLE_ADDR);

        // Phase 2: Migrate to TDX — set measurement + RTMR3
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);

        // SGX quote with old MRENCLAVE no longer works
        address otherAddr = address(0xDDDD);
        bytes memory sgxQuote2 = _buildQuote(TEST_MRENCLAVE, otherAddr);
        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.MeasurementNotActive.selector,
                TEST_MRENCLAVE
            )
        );
        verifier.verifyAttestation(sgxQuote2);

        // TDX quote works
        bytes memory tdxQuote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);
        assertEq(verifier.verifyAttestation(tdxQuote), ORACLE_ADDR);
    }

    // ========== Replay Protection ==========

    function test_verifyAttestation_replayBlocked() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);

        // First call succeeds
        assertEq(verifier.verifyAttestation(quote), ORACLE_ADDR);

        // Replay with same quote reverts
        vm.expectRevert(DcapAttestationVerifier.QuoteAlreadyUsed.selector);
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_tdx_replayBlocked() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);

        // First call succeeds
        assertEq(verifier.verifyAttestation(quote), ORACLE_ADDR);

        // Replay reverts
        vm.expectRevert(DcapAttestationVerifier.QuoteAlreadyUsed.selector);
        verifier.verifyAttestation(quote);
    }

    function test_verifyAttestation_replayAfterRevocation() public {
        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);

        // Deploy marketplace and register oracle
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));
        marketplace.setAttestationVerifier(address(verifier));
        marketplace.registerOracle(quote);
        assertTrue(marketplace.oracles(ORACLE_ADDR));

        // Owner revokes oracle
        marketplace.revokeOracle(ORACLE_ADDR);
        assertFalse(marketplace.oracles(ORACLE_ADDR));

        // Attacker tries to replay same quote — blocked by verifier
        vm.expectRevert(DcapAttestationVerifier.QuoteAlreadyUsed.selector);
        marketplace.registerOracle(quote);

        // Oracle stays revoked
        assertFalse(marketplace.oracles(ORACLE_ADDR));
    }

    function test_verifyAttestation_differentQuotesFromSameEnclave() public {
        verifier.setMeasurement(TEST_MRENCLAVE);

        // Different quotes (different addresses = different boot cycles)
        address addr1 = address(0x1111111111111111111111111111111111111111);
        address addr2 = address(0x2222222222222222222222222222222222222222);
        bytes memory quote1 = _buildQuote(TEST_MRENCLAVE, addr1);
        bytes memory quote2 = _buildQuote(TEST_MRENCLAVE, addr2);

        // Both succeed (different quotes, different hashes)
        assertEq(verifier.verifyAttestation(quote1), addr1);
        assertEq(verifier.verifyAttestation(quote2), addr2);
    }

    // ========== Integration: JJSKIN registerOracle ==========

    function test_e2e_registerOracleViaDcap() public {
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));
        marketplace.setAttestationVerifier(address(verifier));

        verifier.setMeasurement(TEST_MRENCLAVE);
        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);
        marketplace.registerOracle(quote);

        assertTrue(marketplace.oracles(ORACLE_ADDR));
    }

    function test_e2e_registerOracleViaDcap_tdx() public {
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));
        marketplace.setAttestationVerifier(address(verifier));

        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(zeroRtmr3Hash);
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);
        marketplace.registerOracle(quote);

        assertTrue(marketplace.oracles(ORACLE_ADDR));
    }

    function test_e2e_registerOracle_failsWithBadQuote() public {
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));

        DcapAttestationVerifier failVerifier = new DcapAttestationVerifier(address(mockDcapFail));
        failVerifier.setMeasurement(TEST_MRENCLAVE);
        marketplace.setAttestationVerifier(address(failVerifier));

        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);
        vm.expectRevert(DcapAttestationVerifier.DcapVerificationFailed.selector);
        marketplace.registerOracle(quote);
    }

    function test_e2e_measurementRotation() public {
        MockUSDC usdc = new MockUSDC();
        MockSteamAccountFactory factory = new MockSteamAccountFactory();
        JJSKIN marketplace = new JJSKIN(address(usdc), address(factory));
        marketplace.setAttestationVerifier(address(verifier));

        // Phase 1: Deploy v1
        bytes32 mrV1 = bytes32(uint256(1));
        address oracleV1 = address(0xAAAA);
        verifier.setMeasurement(mrV1);
        marketplace.registerOracle(_buildQuote(mrV1, oracleV1));
        assertTrue(marketplace.oracles(oracleV1));

        // Phase 2: Deploy v2 — old build implicitly blocked
        bytes32 mrV2 = bytes32(uint256(2));
        address oracleV2 = address(0xBBBB);
        verifier.setMeasurement(mrV2);

        // v1 build can no longer register
        address staleAddr = address(0xCCCC);
        vm.expectRevert(
            abi.encodeWithSelector(DcapAttestationVerifier.MeasurementNotActive.selector, mrV1)
        );
        marketplace.registerOracle(_buildQuote(mrV1, staleAddr));

        // v2 registers successfully
        marketplace.registerOracle(_buildQuote(mrV2, oracleV2));
        assertTrue(marketplace.oracles(oracleV2));

        // v1 oracle still active (lazy invalidation) — must explicitly revoke
        assertTrue(marketplace.oracles(oracleV1));
        marketplace.revokeOracle(oracleV1);
        assertFalse(marketplace.oracles(oracleV1));
    }

    // ========== RTMR[3] Tests ==========

    function test_tdx_rtmr3_match() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(testRtmr3Hash);
        bytes memory quote = _buildTdxQuoteWithRtmr3(
            TEST_MRTD_PART1, TEST_MRTD_PART2,
            TEST_RTMR3_PART1, TEST_RTMR3_PART2,
            ORACLE_ADDR
        );

        address result = verifier.verifyAttestation(quote);
        assertEq(result, ORACLE_ADDR);
    }

    function test_tdx_rtmr3_mismatch() public {
        verifier.setMeasurement(testMrtdHash);
        verifier.setRtmr3(testRtmr3Hash);

        // Build quote with wrong RTMR3 (all zeros instead of test data)
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);

        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.Rtmr3NotActive.selector,
                zeroRtmr3Hash
            )
        );
        verifier.verifyAttestation(quote);
    }

    function test_tdx_rtmr3_notSet_reverts() public {
        // activeRtmr3 = bytes32(0), quote has all-zero RTMR3
        // keccak256(zeros_48) != bytes32(0), so it reverts
        verifier.setMeasurement(testMrtdHash);
        bytes memory quote = _buildTdxQuote(TEST_MRTD_PART1, TEST_MRTD_PART2, ORACLE_ADDR);

        vm.expectRevert(
            abi.encodeWithSelector(
                DcapAttestationVerifier.Rtmr3NotActive.selector,
                zeroRtmr3Hash
            )
        );
        verifier.verifyAttestation(quote);
    }

    function test_setRtmr3_onlyOwner() public {
        vm.prank(address(0xbad));
        vm.expectRevert();
        verifier.setRtmr3(testRtmr3Hash);
    }

    function test_setRtmr3_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit DcapAttestationVerifier.Rtmr3Set(testRtmr3Hash, bytes32(0));
        verifier.setRtmr3(testRtmr3Hash);
    }

    function test_sgx_ignores_rtmr3() public {
        // SGX quotes should work regardless of activeRtmr3 setting
        verifier.setMeasurement(TEST_MRENCLAVE);
        verifier.setRtmr3(testRtmr3Hash); // non-zero RTMR3 set

        bytes memory quote = _buildQuote(TEST_MRENCLAVE, ORACLE_ADDR);
        address result = verifier.verifyAttestation(quote);
        assertEq(result, ORACLE_ADDR);
    }

    // ========== Ownership Transfer ==========

    function test_ownershipTransfer() public {
        address newOwner = address(0xbeef);
        verifier.transferOwnership(newOwner);

        vm.prank(newOwner);
        verifier.acceptOwnership();

        assertEq(verifier.owner(), newOwner);
    }
}
