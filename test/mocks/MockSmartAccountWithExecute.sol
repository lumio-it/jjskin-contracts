// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../../src/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title MockSmartAccountWithExecute
 * @notice Mock smart account with execute() function for integration testing
 * @dev Extends MockSmartAccount with an execute function that forwards calls
 */
contract MockSmartAccountWithExecute is IERC1271, EIP712 {
    using ECDSA for bytes32;

    address public owner;

    constructor(address _owner) EIP712("CS2MarketplaceV2_Optimized", "2") {
        owner = _owner;
    }

    /**
     * @notice Validates a signature according to ERC-1271
     * @param hash The hash of the data that was signed
     * @param signature The signature to validate
     * @return magicValue Returns 0x1626ba7e if signature is valid
     */
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view override returns (bytes4 magicValue) {
        // Recover the signer from the signature
        address signer = hash.recover(signature);

        // Check if the signer is the owner
        if (signer == owner) {
            return 0x1626ba7e; // ERC-1271 magic value
        }

        return 0xffffffff; // Invalid signature
    }

    /**
     * @notice Execute a call to another contract
     * @param target The address to call
     * @param value The ETH value to send
     * @param callData The calldata to forward
     * @dev Simple execute function for testing - no access control (owner can call via EOA)
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata callData
    ) external payable returns (bytes memory) {
        // In production, would check msg.sender == owner
        // For testing, we allow any caller since we control the test environment

        (bool success, bytes memory result) = target.call{value: value}(callData);

        if (!success) {
            // Forward the revert reason
            assembly {
                let ptr := mload(0x40)
                let size := returndatasize()
                returndatacopy(ptr, 0, size)
                revert(ptr, size)
            }
        }

        return result;
    }

    // Allow receiving ETH
    receive() external payable {}

    // Allow calling any function (for testing flexibility)
    fallback() external payable {}
}
