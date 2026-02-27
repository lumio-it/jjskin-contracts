// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../../src/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title MockSmartAccount
 * @notice Mock smart account that implements ERC-1271 for testing
 * @dev Validates signatures from a designated owner EOA
 */
contract MockSmartAccount is IERC1271, EIP712 {
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
    
    /// @notice Relay a call through this smart account (owner only)
    /// @dev Used by deploy scripts where vm.prank is unavailable
    function execute(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        (bool success, bytes memory result) = target.call(data);
        require(success, "execute failed");
        return result;
    }

    // Allow receiving ETH
    receive() external payable {}

    // Allow calling any function (for testing flexibility)
    fallback() external payable {}
}