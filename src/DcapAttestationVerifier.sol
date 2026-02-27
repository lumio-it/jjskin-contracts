// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "./interfaces/IAttestationVerifier.sol";

/// @notice Minimal interface for Automata's deployed DCAP attestation contract
interface IAutomataDcapAttestation {
    /// @notice Verify a DCAP quote on-chain (checks signature chain, TCB, PCK certs)
    /// @param rawQuote The raw SGX/TDX DCAP quote bytes
    /// @return success Whether the quote passed verification
    /// @return output Parsed attestation output (unused — we extract from rawQuote directly)
    function verifyAndAttestOnChain(bytes calldata rawQuote)
        external
        returns (bool success, bytes memory output);
}

/// @title DcapAttestationVerifier
/// @notice Verifies Intel SGX/TDX DCAP attestation quotes via Automata's on-chain verifier
///         and extracts the oracle signing address from the quote's reportData field.
///
/// @dev Supports both SGX (Quote V3) and TDX (Quote V4) quotes, auto-detected from
///      the TEE type field in the quote header (bytes 4-7):
///
///      SGX Quote V3 (TEE type = 0x00000000):
///      - Report Body: 384 bytes starting at offset 48
///        - MRENCLAVE (32B) at body offset 64 (abs 112)
///        - reportData (64B) at body offset 320 (abs 368)
///      - activeMeasurement = raw MRENCLAVE (32 bytes)
///
///      TDX Quote V4 (TEE type = 0x81000000):
///      - TD Report Body: 584 bytes starting at offset 48
///        - MRTD (48B) at body offset 136 (abs 184)
///        - reportData (64B) at body offset 520 (abs 568)
///      - activeMeasurement = keccak256(MRTD) (48 bytes hashed to 32 bytes)
///
///      The oracle writes its Ethereum address (20 bytes, left-aligned) into
///      reportData before requesting the quote from the TEE platform.
///
///      Single active measurement design (industry pattern):
///      - Only one measurement can be active at a time (SGX or TDX)
///      - setMeasurement() implicitly revokes the old build
///      - Already-registered oracles stay active (lazy invalidation)
///        until explicitly revoked via JJSKIN.revokeOracle()
contract DcapAttestationVerifier is IAttestationVerifier, Ownable2Step {
    /// @notice Automata DCAP attestation contract (deployed on Arbitrum)
    IAutomataDcapAttestation public immutable dcapAttestation;

    /// @notice The single active measurement (MRENCLAVE for SGX, keccak256(MRTD) for TDX)
    bytes32 public activeMeasurement;

    /// @notice Active RTMR[3] hash (keccak256 of 48-byte RTMR3 from TDX quote).
    ///         Must be set via setRtmr3() before TDX oracles can register.
    bytes32 public activeRtmr3;

    /// @notice Used quote hashes (prevents replay after oracle revocation)
    mapping(bytes32 => bool) public usedQuotes;

    // Quote header
    uint256 private constant QUOTE_HEADER_SIZE = 48;

    // TEE type field at bytes 4-7 of header (little-endian uint32 read as big-endian bytes4)
    bytes4 private constant TEE_TYPE_SGX = 0x00000000;
    bytes4 private constant TEE_TYPE_TDX = 0x81000000;

    // SGX offsets (Quote V3, Report Body = 384 bytes)
    uint256 private constant SGX_REPORT_BODY_SIZE = 384;
    uint256 private constant SGX_MRENCLAVE_OFFSET = QUOTE_HEADER_SIZE + 64;    // abs 112
    uint256 private constant SGX_REPORT_DATA_OFFSET = QUOTE_HEADER_SIZE + 320; // abs 368
    uint256 private constant SGX_MIN_QUOTE_SIZE = QUOTE_HEADER_SIZE + SGX_REPORT_BODY_SIZE; // 432

    // TDX offsets (Quote V4, TD Report Body = 584 bytes)
    uint256 private constant TDX_REPORT_BODY_SIZE = 584;
    uint256 private constant TDX_MRTD_OFFSET = QUOTE_HEADER_SIZE + 136;       // abs 184
    uint256 private constant TDX_MRTD_SIZE = 48;
    uint256 private constant TDX_RTMR3_OFFSET = QUOTE_HEADER_SIZE + 472;     // abs 520
    uint256 private constant TDX_RTMR3_SIZE = 48;
    uint256 private constant TDX_REPORT_DATA_OFFSET = QUOTE_HEADER_SIZE + 520; // abs 568
    uint256 private constant TDX_MIN_QUOTE_SIZE = QUOTE_HEADER_SIZE + TDX_REPORT_BODY_SIZE; // 632

    error DcapVerificationFailed();
    error MeasurementNotActive(bytes32 measurement);
    error Rtmr3NotActive(bytes32 rtmr3);
    error NoActiveMeasurement();
    error QuoteTooShort(uint256 length);
    error ZeroAddressInReportData();
    error QuoteAlreadyUsed();
    error UnsupportedTeeType(bytes4 teeType);

    event MeasurementSet(bytes32 indexed newMeasurement, bytes32 indexed oldMeasurement);
    event Rtmr3Set(bytes32 indexed newRtmr3, bytes32 indexed oldRtmr3);

    constructor(address _dcapAttestation) Ownable(msg.sender) {
        dcapAttestation = IAutomataDcapAttestation(_dcapAttestation);
    }

    /// @inheritdoc IAttestationVerifier
    function verifyAttestation(bytes calldata attestation)
        external
        override
        returns (address oracleAddress)
    {
        if (attestation.length < QUOTE_HEADER_SIZE) {
            revert QuoteTooShort(attestation.length);
        }

        // 0. Must have an active measurement
        bytes32 active = activeMeasurement;
        if (active == bytes32(0)) revert NoActiveMeasurement();

        // 1. Replay protection — each quote can only be used once
        bytes32 quoteHash = keccak256(attestation);
        if (usedQuotes[quoteHash]) revert QuoteAlreadyUsed();
        usedQuotes[quoteHash] = true;

        // 2. Verify quote via Automata DCAP (signature chain, TCB, PCK certs)
        (bool success, ) = dcapAttestation.verifyAndAttestOnChain(attestation);
        if (!success) revert DcapVerificationFailed();

        // 3. Detect TEE type and extract measurement + oracle address
        bytes4 teeType = bytes4(attestation[4:8]);
        bytes32 measurement;

        if (teeType == TEE_TYPE_SGX) {
            if (attestation.length < SGX_MIN_QUOTE_SIZE) {
                revert QuoteTooShort(attestation.length);
            }
            // MRENCLAVE: 32 bytes at abs offset 112
            measurement = bytes32(attestation[SGX_MRENCLAVE_OFFSET:SGX_MRENCLAVE_OFFSET + 32]);
            // Oracle address: first 20 bytes of reportData at abs offset 368
            oracleAddress = address(bytes20(attestation[SGX_REPORT_DATA_OFFSET:SGX_REPORT_DATA_OFFSET + 20]));
        } else if (teeType == TEE_TYPE_TDX) {
            if (attestation.length < TDX_MIN_QUOTE_SIZE) {
                revert QuoteTooShort(attestation.length);
            }
            // MRTD: 48 bytes at abs offset 184 → hash to bytes32
            measurement = keccak256(attestation[TDX_MRTD_OFFSET:TDX_MRTD_OFFSET + TDX_MRTD_SIZE]);
            // Oracle address: first 20 bytes of reportData at abs offset 568
            oracleAddress = address(bytes20(attestation[TDX_REPORT_DATA_OFFSET:TDX_REPORT_DATA_OFFSET + 20]));

            // Verify RTMR[3] (compose-hash from dstack) — always required for TDX
            bytes32 rtmr3 = keccak256(attestation[TDX_RTMR3_OFFSET:TDX_RTMR3_OFFSET + TDX_RTMR3_SIZE]);
            if (rtmr3 != activeRtmr3) revert Rtmr3NotActive(rtmr3);
        } else {
            revert UnsupportedTeeType(teeType);
        }

        // 4. Verify measurement matches active build
        if (measurement != active) {
            revert MeasurementNotActive(measurement);
        }

        // 5. Verify address is non-zero
        if (oracleAddress == address(0)) revert ZeroAddressInReportData();
    }

    /// @notice Set the active measurement
    /// @dev For SGX: pass raw MRENCLAVE (32 bytes).
    ///      For TDX: pass keccak256(MRTD) (48-byte MRTD hashed to 32 bytes).
    ///      Replaces any previous measurement. Only one build can register oracles at a time.
    ///      Already-registered oracles from the old build stay active in JJSKIN.oracles
    ///      until explicitly revoked via JJSKIN.revokeOracle().
    /// @param measurement The 32-byte measurement hash
    function setMeasurement(bytes32 measurement) external onlyOwner {
        bytes32 old = activeMeasurement;
        activeMeasurement = measurement;
        emit MeasurementSet(measurement, old);
    }

    /// @notice Set the active RTMR[3] hash for dstack compose verification
    /// @dev Pass keccak256(RTMR3) where RTMR3 is the 48-byte runtime measurement
    ///      register extended with the compose-hash by dstack.
    ///      Must be set before TDX oracles can register.
    /// @param rtmr3Hash The 32-byte keccak256 hash of the expected RTMR[3] value
    function setRtmr3(bytes32 rtmr3Hash) external onlyOwner {
        bytes32 old = activeRtmr3;
        activeRtmr3 = rtmr3Hash;
        emit Rtmr3Set(rtmr3Hash, old);
    }
}
