// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {Test, console2} from "forge-std/Test.sol";
import {CS2AaveVault, IPool, IAToken} from "../src/CS2AaveVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "@openzeppelin/contracts/interfaces/IERC4626.sol";

// Mock Aave contracts
contract MockAavePool {
    IERC20 public usdc;
    LocalMockAToken public aToken;
    
    constructor(IERC20 _usdc, LocalMockAToken _aToken) {
        usdc = _usdc;
        aToken = _aToken;
    }
    
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16
    ) external {
        require(asset == address(usdc), "Invalid asset");
        usdc.transferFrom(msg.sender, address(this), amount);
        aToken.poolMint(onBehalfOf, amount);
    }
    
    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external returns (uint256) {
        require(asset == address(usdc), "Invalid asset");
        uint256 aTokenBalance = aToken.balanceOf(msg.sender);
        uint256 toWithdraw = amount > aTokenBalance ? aTokenBalance : amount;
        
        if (toWithdraw > 0) {
            aToken.burn(msg.sender, toWithdraw);
            usdc.transfer(to, toWithdraw);
        }
        
        return toWithdraw;
    }
    
    // Simulate yield generation by minting extra aTokens to vault
    // This simulates the vault earning yield on its deposits
    function simulateYield(address vault, uint256 yieldAmount) external {
        aToken.poolMint(vault, yieldAmount);
    }
}

contract LocalMockAToken is MockUSDC {
    address public immutable UNDERLYING_ASSET_ADDRESS;
    address public pool;
    
    constructor(address underlying) {
        UNDERLYING_ASSET_ADDRESS = underlying;
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
}

contract CS2AaveVaultTest is Test {
    CS2AaveVault public vault;
    MockUSDC public usdc;
    LocalMockAToken public aToken;
    MockAavePool public aavePool;
    
    address public owner;
    address public marketplace;
    address public user1;
    address public user2;
    
    event BufferUpdated(uint256 oldBuffer, uint256 newBuffer);
    event EmergencyModeActivated(address indexed activator);
    event EmergencyModeDeactivated(address indexed deactivator);
    event YieldHarvested(uint256 amount, address indexed recipient);
    
    function setUp() public {
        owner = makeAddr("owner");
        marketplace = makeAddr("marketplace");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        
        // Deploy mocks
        vm.startPrank(owner);
        usdc = new MockUSDC();
        aToken = new LocalMockAToken(address(usdc));
        aavePool = new MockAavePool(usdc, aToken);
        aToken.setPool(address(aavePool));
        
        // Deploy vault
        vault = new CS2AaveVault(
            usdc,
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            marketplace,
            owner
        );
        
        // Fund users (as owner of MockUSDC)
        usdc.mint(user1, 10000e6); // 10,000 USDC
        usdc.mint(user2, 10000e6);
        usdc.mint(marketplace, 50000e6); // 50,000 USDC
        
        vm.stopPrank();
        
        // Approve vault
        vm.prank(user1);
        usdc.approve(address(vault), type(uint256).max);
        
        vm.prank(user2);
        usdc.approve(address(vault), type(uint256).max);
        
        vm.prank(marketplace);
        usdc.approve(address(vault), type(uint256).max);
    }
    
    // ========== Basic Functionality Tests ==========
    
    function testDeposit() public {
        uint256 depositAmount = 1000e6; // 1000 USDC
        
        vm.prank(user1);
        uint256 shares = vault.deposit(depositAmount, user1);
        
        assertEq(shares, depositAmount); // 1:1 initially
        assertEq(vault.balanceOf(user1), shares);
        assertEq(vault.totalAssets(), depositAmount);
    }
    
    function testWithdraw() public {
        uint256 depositAmount = 1000e6;
        
        vm.prank(user1);
        vault.deposit(depositAmount, user1);
        
        vm.prank(user1);
        uint256 assets = vault.withdraw(500e6, user1, user1);
        
        assertEq(assets, 500e6);
        assertEq(usdc.balanceOf(user1), 9500e6); // 10000 - 1000 + 500
        assertEq(vault.totalAssets(), 500e6);
    }
    
    function testRedeem() public {
        uint256 depositAmount = 1000e6;
        
        vm.prank(user1);
        uint256 shares = vault.deposit(depositAmount, user1);
        
        vm.prank(user1);
        uint256 assets = vault.redeem(shares / 2, user1, user1);
        
        assertEq(assets, 500e6);
        assertEq(vault.balanceOf(user1), shares / 2);
    }
    
    // ========== Rebalancing Tests ==========
    
    function testAutoRebalanceOnDeposit() public {
        // First deposit
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Should keep buffer (10% = 100 USDC)
        uint256 liquidBalance = usdc.balanceOf(address(vault));
        uint256 aaveBalance = aToken.balanceOf(address(vault));
        
        // With 10% buffer, should keep ~100 USDC liquid
        assertApproxEqAbs(liquidBalance, 100e6, 10e6);
        assertApproxEqAbs(aaveBalance, 900e6, 10e6);
    }
    
    function testManualRebalance() public {
        // Test that manual rebalance works correctly
        // First deposit funds
        vm.prank(user1);
        vault.deposit(100e6, user1);
        
        // After deposit, should be auto-rebalanced (10% liquid, 90% in Aave)
        assertApproxEqAbs(usdc.balanceOf(address(vault)), 10e6, 1e6);
        assertApproxEqAbs(aToken.balanceOf(address(vault)), 90e6, 1e6);
        
        // Simulate some drift by minting extra USDC to the vault
        // This simulates fees or other deposits that bypass rebalancing
        vm.prank(owner);
        usdc.mint(address(vault), 50e6);
        
        // Now we have too much liquid (60e6 instead of optimal 15e6)
        assertEq(usdc.balanceOf(address(vault)), 60e6);
        
        // Manual rebalance by owner
        vm.prank(owner);
        vault.rebalance();
        
        // Should now be rebalanced to 10% of total (150e6 total, so 15e6 liquid)
        uint256 liquidBalance = usdc.balanceOf(address(vault));
        uint256 aaveBalance = aToken.balanceOf(address(vault));
        
        assertApproxEqAbs(liquidBalance, 15e6, 2e6); // ~10% buffer of 150e6
        assertApproxEqAbs(aaveBalance, 135e6, 2e6);
    }
    
    function testRebalanceByMarketplace() public {
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Marketplace can trigger rebalance
        vm.prank(marketplace);
        vault.rebalance();
        
        // Should work without reverting
        assertTrue(vault.totalAssets() > 0);
    }
    
    // ========== Buffer Management Tests ==========
    
    function testSetBuffer() public {
        uint256 newBuffer = 2000; // 20%
        
        vm.expectEmit(true, true, false, true);
        emit BufferUpdated(1000, newBuffer);
        
        vm.prank(owner);
        vault.setBuffer(newBuffer);
        
        assertEq(vault.bufferBasisPoints(), newBuffer);
    }
    
    function testSetBufferTooHigh() public {
        vm.prank(owner);
        vm.expectRevert(CS2AaveVault.InvalidBuffer.selector);
        vault.setBuffer(6000); // 60% > 50% max
    }
    
    function testBufferAffectsRebalancing() public {
        // Set higher buffer
        vm.prank(owner);
        vault.setBuffer(3000); // 30%
        
        // Deposit
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Should keep 30% liquid
        uint256 liquidBalance = usdc.balanceOf(address(vault));
        assertApproxEqAbs(liquidBalance, 300e6, 30e6);
    }
    
    // ========== Yield Harvesting Tests ==========
    
    function testHarvestYieldByMarketplace() public {
        // Setup: deposit and generate yield
        vm.prank(marketplace);
        vault.deposit(10000e6, marketplace);
        
        // Simulate yield in Aave (5% = 500 USDC)
        vm.prank(owner);
        usdc.mint(address(aavePool), 500e6);
        aavePool.simulateYield(address(vault), 500e6);
        
        // Harvest yield
        vm.prank(marketplace);
        uint256 harvested = vault.harvestYield(marketplace);
        
        // Note: Yield calculation is complex with shares
        // This is a simplified test
        assertTrue(harvested > 0);
    }
    
    function testHarvestYieldByOwner() public {
        // Setup
        vm.prank(user1);
        vault.deposit(10000e6, user1);
        
        // Generate yield
        vm.prank(owner);
        usdc.mint(address(aavePool), 500e6);
        aavePool.simulateYield(address(vault), 500e6);
        
        // Owner can harvest to any recipient
        address feeRecipient = makeAddr("feeRecipient");
        
        vm.prank(owner);
        uint256 harvested = vault.harvestYield(feeRecipient);
        
        // Check recipient got yield
        assertTrue(usdc.balanceOf(feeRecipient) > 0);
    }
    
    function testHarvestYieldUnauthorized() public {
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Random user cannot harvest
        vm.prank(user2);
        vm.expectRevert(CS2AaveVault.Unauthorized.selector);
        vault.harvestYield(user2);
    }
    
    // ========== Emergency Mode Tests ==========
    
    function testActivateEmergencyMode() public {
        // Deposit funds
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Some should be in Aave
        uint256 aaveBalanceBefore = aToken.balanceOf(address(vault));
        assertTrue(aaveBalanceBefore > 0);
        
        // Activate emergency
        vm.expectEmit(true, false, false, true);
        emit EmergencyModeActivated(owner);
        
        vm.prank(owner);
        vault.activateEmergencyMode();
        
        // All funds should be withdrawn from Aave
        assertEq(aToken.balanceOf(address(vault)), 0);
        assertEq(usdc.balanceOf(address(vault)), 1000e6);
        assertTrue(vault.emergencyMode());
    }
    
    function testEmergencyModeBlocksDeposits() public {
        vm.prank(owner);
        vault.activateEmergencyMode();
        
        // Cannot deposit in emergency mode
        vm.prank(user1);
        vm.expectRevert(CS2AaveVault.EmergencyModeActive.selector);
        vault.deposit(100e6, user1);
    }
    
    function testEmergencyModeAllowsWithdrawals() public {
        // Deposit first
        vm.prank(user1);
        vault.deposit(1000e6, user1);
        
        // Activate emergency
        vm.prank(owner);
        vault.activateEmergencyMode();
        
        // Can still withdraw
        vm.prank(user1);
        uint256 withdrawn = vault.withdraw(500e6, user1, user1);
        
        assertEq(withdrawn, 500e6);
        assertEq(usdc.balanceOf(user1), 9500e6);
    }
    
    function testDeactivateEmergencyMode() public {
        // Activate then deactivate
        vm.prank(owner);
        vault.activateEmergencyMode();
        
        vm.expectEmit(true, false, false, true);
        emit EmergencyModeDeactivated(owner);
        
        vm.prank(owner);
        vault.deactivateEmergencyMode();
        
        assertFalse(vault.emergencyMode());
        
        // Can deposit again
        vm.prank(user1);
        uint256 shares = vault.deposit(100e6, user1);
        assertTrue(shares > 0);
    }
    
    // ========== Access Control Tests ==========
    
    function testOnlyOwnerCanSetBuffer() public {
        vm.prank(user1);
        vm.expectRevert();
        vault.setBuffer(2000);
    }
    
    function testOnlyOwnerCanActivateEmergency() public {
        vm.prank(user1);
        vm.expectRevert();
        vault.activateEmergencyMode();
    }
    
    function testRebalanceAccessControl() public {
        // User cannot rebalance
        vm.prank(user1);
        vm.expectRevert(CS2AaveVault.Unauthorized.selector);
        vault.rebalance();
        
        // Owner can
        vm.prank(owner);
        vault.rebalance(); // Should not revert
        
        // Marketplace can
        vm.prank(marketplace);
        vault.rebalance(); // Should not revert
    }
    
    // ========== Integration Tests ==========
    
    function testFullCycle() public {
        // 1. Multiple deposits
        vm.prank(user1);
        vault.deposit(5000e6, user1);
        
        vm.prank(user2);
        vault.deposit(3000e6, user2);
        
        // 2. Generate yield
        vm.prank(owner);
        usdc.mint(address(aavePool), 400e6);
        aavePool.simulateYield(address(vault), 400e6);
        
        // 3. Partial withdrawal
        vm.prank(user1);
        vault.withdraw(1000e6, user1, user1);
        
        // 4. Harvest yield
        vm.prank(marketplace);
        vault.harvestYield(marketplace);
        
        // 5. More deposits
        vm.prank(user1);
        vault.deposit(2000e6, user1);
        
        // 6. Full redemption for user2
        uint256 user2Shares = vault.balanceOf(user2);
        vm.prank(user2);
        vault.redeem(user2Shares, user2, user2);
        
        // Verify final state
        assertEq(vault.balanceOf(user2), 0);
        assertTrue(vault.totalAssets() > 0);
    }
    
    // ========== Edge Cases ==========
    
    function testDepositZero() public {
        vm.prank(user1);
        uint256 shares = vault.deposit(0, user1);
        assertEq(shares, 0); // Zero deposit returns zero shares
        assertEq(vault.balanceOf(user1), 0);
    }
    
    function testWithdrawMoreThanBalance() public {
        vm.prank(user1);
        vault.deposit(100e6, user1);
        
        vm.prank(user1);
        vm.expectRevert();
        vault.withdraw(200e6, user1, user1);
    }
    
    function testRedeemMoreSharesThanOwned() public {
        vm.prank(user1);
        uint256 shares = vault.deposit(100e6, user1);
        
        vm.prank(user1);
        vm.expectRevert();
        vault.redeem(shares * 2, user1, user1);
    }
}