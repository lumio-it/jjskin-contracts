// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";
import "../../src/CS2AaveVault.sol";

/// @title EmergencyWithdrawFromVault Tests
/// @notice Tests for emergencyWithdrawFromVault() — previously ZERO coverage
contract EmergencyWithdrawFromVaultTest is BaseTest {
    CS2AaveVault public vault;

    function setUp() public override {
        super.setUp();
        _deployAndConfigureVault();
    }

    function _deployAndConfigureVault() internal {
        vm.startPrank(owner);
        vault = new CS2AaveVault(
            IERC20(address(usdc)),
            IPool(address(aavePool)),
            IAToken(address(aToken)),
            address(marketplace),
            owner
        );
        marketplace.setYieldVault(address(vault));
        vm.stopPrank();
    }

    /// @notice Deposit funds to vault so there are shares to withdraw
    function _depositToVault(uint256 amount) internal {
        // Mint USDC directly to marketplace so it can deposit
        vm.startPrank(owner);
        usdc.mint(address(marketplace), amount);
        marketplace.depositIdleFundsToVault();
        vm.stopPrank();
    }

    // ========== Tests ==========

    function test_emergencyWithdrawFromVault_basic() public {
        // Deposit enough to vault
        _depositToVault(1_000_000_000); // 1000 USDC

        uint256 sharesBefore = marketplace.totalVaultShares();
        assertGt(sharesBefore, 0, "should have shares");

        uint256 contractBalBefore = usdc.balanceOf(address(marketplace));

        vm.prank(owner);
        marketplace.emergencyWithdrawFromVault();

        // Shares and deposits should be reset
        assertEq(marketplace.totalVaultShares(), 0, "shares should be zero");
        assertEq(marketplace.totalVaultDeposits(), 0, "deposits should be zero");

        // USDC returned to marketplace
        uint256 contractBalAfter = usdc.balanceOf(address(marketplace));
        assertGt(contractBalAfter, contractBalBefore, "USDC should return to marketplace");
    }

    function test_emergencyWithdrawFromVault_onlyOwner() public {
        _depositToVault(1_000_000_000);

        vm.prank(attacker);
        vm.expectRevert();
        marketplace.emergencyWithdrawFromVault();
    }

    function test_emergencyWithdrawFromVault_noVault() public {
        // Deploy fresh marketplace without vault
        vm.prank(owner);
        JJSKIN fresh = new JJSKIN(
            address(usdc),
            address(walletFactory)
        );

        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        fresh.emergencyWithdrawFromVault();
    }

    function test_emergencyWithdrawFromVault_noShares() public {
        // Vault is set but no deposits made
        vm.prank(owner);
        vm.expectRevert(JJSKIN.InvalidInput.selector);
        marketplace.emergencyWithdrawFromVault();
    }

    function test_emergencyWithdrawFromVault_preservesUserBalances() public {
        // Create a purchase and settle so seller has balance
        _createListingAndPurchase(ASSET_ID, seller, buyer, ITEM_PRICE);
        vm.prank(seller);
        marketplace.commitTradeOffer(ASSET_ID, 111);
        _oracleClaim(ASSET_ID);

        uint256 sellerBal = marketplace.userBalances(seller);
        assertGt(sellerBal, 0, "seller should have balance");

        // Deposit remaining contract funds to vault
        _depositToVault(1_000_000_000);

        // Emergency withdraw
        vm.prank(owner);
        marketplace.emergencyWithdrawFromVault();

        // Seller balance should be unchanged
        assertEq(marketplace.userBalances(seller), sellerBal, "user balance should be preserved");

        // Seller should still be able to withdraw
        vm.prank(seller);
        marketplace.withdrawBalance();
        assertEq(marketplace.userBalances(seller), 0, "balance should be zero after withdraw");
    }
}
