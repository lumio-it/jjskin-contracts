// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title MockUSDC
 * @notice Mock USDC token for testing on testnets
 * @dev Mimics USDC with 6 decimals and mint function for testing
 */
contract MockUSDC is ERC20, Ownable {
    uint8 private constant DECIMALS = 6;
    
    constructor() ERC20("USD Coin (Mock)", "USDC") Ownable(msg.sender) {}
    
    function decimals() public pure override returns (uint8) {
        return DECIMALS;
    }
    
    /**
     * @notice Mint tokens for testing
     * @param to Recipient address
     * @param amount Amount to mint (in base units, 6 decimals)
     */
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }
    
    /**
     * @notice Public faucet function for testnet
     * @dev Allows anyone to mint 1000 USDC for testing
     */
    function faucet() external {
        uint256 amount = 1000 * 10**DECIMALS; // 1000 USDC
        _mint(msg.sender, amount);
    }
}