// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/// @title IAttestationVerifier
/// @notice Interface for TEE attestation verification
/// @dev Implementations verify platform-specific attestations (TDX quotes, SGX DCAP, etc.)
///      and extract the oracle signing address from the attestation data.
interface IAttestationVerifier {
    /// @notice Verify TEE attestation and extract the oracle signing address
    /// @dev Reverts if attestation is invalid
    /// @param attestation Raw attestation data (TDX quote, SGX DCAP, etc.)
    /// @return oracleAddress The Ethereum address authorized by the attestation
    function verifyAttestation(bytes calldata attestation) external returns (address oracleAddress);
}
