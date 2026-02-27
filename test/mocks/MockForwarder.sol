// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/**
 * @dev Simple mock forwarder for testing gasless transactions
 */
contract MockForwarder {
    mapping(address => uint256) public nonces;
    
    function execute(
        address from,
        address to,
        uint256 value,
        uint256 gas,
        uint256 nonce,
        bytes calldata data
    ) external payable returns (bool success, bytes memory returndata) {
        require(nonces[from] == nonce, "Invalid nonce");
        nonces[from]++;
        
        // Append from address to calldata (ERC2771 pattern)
        bytes memory forwardedData = abi.encodePacked(data, from);
        
        // Execute the call
        (success, returndata) = to.call{value: value, gas: gas}(forwardedData);
    }
    
    function getNonce(address from) external view returns (uint256) {
        return nonces[from];
    }
}