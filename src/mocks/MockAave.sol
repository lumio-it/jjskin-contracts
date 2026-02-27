// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockUSDC} from "./MockUSDC.sol";

/**
 * @title MockAavePool
 * @notice Mock Aave V3 pool for testing
 */
contract MockAavePool {
    IERC20 public usdc;
    MockAToken public aToken;
    
    constructor(IERC20 _usdc, MockAToken _aToken) {
        usdc = _usdc;
        aToken = _aToken;
    }
    
    function supply(address asset, uint256 amount, address onBehalfOf, uint16) external {
        require(asset == address(usdc), "Invalid asset");
        usdc.transferFrom(msg.sender, address(this), amount);
        aToken.poolMint(onBehalfOf, amount);
    }
    
    function withdraw(address asset, uint256 amount, address to) external returns (uint256) {
        require(asset == address(usdc), "Invalid asset");
        uint256 aTokenBalance = aToken.balanceOf(msg.sender);
        uint256 toWithdraw = amount > aTokenBalance ? aTokenBalance : amount;
        
        if (amount == type(uint256).max) {
            toWithdraw = aTokenBalance;
        }
        
        if (toWithdraw > 0) {
            aToken.burn(msg.sender, toWithdraw);
            usdc.transfer(to, toWithdraw);
        }
        
        return toWithdraw;
    }
}

/**
 * @title MockAToken
 * @notice Mock Aave aUSDC token for testing
 */
contract MockAToken is MockUSDC {
    address public immutable UNDERLYING_ASSET_ADDRESS;
    address public pool;
    
    constructor(address _underlying) {
        UNDERLYING_ASSET_ADDRESS = _underlying;
    }
    
    function setPool(address _pool) external onlyOwner {
        pool = _pool;
    }
    
    function poolMint(address to, uint256 amount) external {
        require(msg.sender == pool, "Only pool can mint");
        _mint(to, amount);
    }
    
    function burn(address from, uint256 amount) external {
        _burn(from, amount);
    }
    
    function scaledBalanceOf(address user) external view returns (uint256) {
        return balanceOf(user);
    }
    
    function getScaledUserBalanceAndSupply(address user) external view returns (uint256, uint256) {
        return (balanceOf(user), totalSupply());
    }
}