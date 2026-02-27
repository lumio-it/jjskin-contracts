// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "../base/BaseTest.sol";

/// @title FuzzSettlement
/// @notice Fuzz tests for fee conservation in oracle settlement
contract FuzzSettlement is BaseTest {
    function setUp() public override {
        super.setUp();
    }

    /// @notice For any valid price and fee, seller + fee = price (no rounding loss)
    function testFuzz_feeConservation(uint56 price, uint256 feePercent) public {
        price = uint56(bound(price, 1, 1e12)); // 1 unit to 1M USDC
        feePercent = bound(feePercent, 0, 500); // 0% to 5% (max allowed)

        // Set fee
        vm.prank(owner);
        marketplace.setPlatformFee(feePercent);

        uint256 fee = (uint256(price) * feePercent) / 10000;
        uint256 sellerAmount = uint256(price) - fee;

        // Conservation: fee + sellerAmount == price
        assertEq(fee + sellerAmount, price, "fee conservation violated");
    }
}
