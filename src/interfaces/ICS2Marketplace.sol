// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/**
 * @title ICS2Marketplace
 * @notice Interface for the CS2Marketplace contract
 */
interface ICS2Marketplace {
    function owner() external view returns (address);
    function setTreasury(address _treasury) external;
}