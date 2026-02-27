// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

/**
 * @title ISteamAccountFactory
 * @notice Interface for the Steam Account Factory
 */
interface ISteamAccountFactory {
    /**
     * @notice Check if a wallet address was created by this factory
     * @param wallet The wallet address to check
     * @return True if the wallet was created by this factory
     */
    function isRegistered(address wallet) external view returns (bool);
    
    /**
     * @notice Get the Steam ID for a given wallet address
     * @param wallet The wallet address to query
     * @return steamId The Steam ID associated with this wallet (0 if none)
     */
    function getSteamIdByWallet(address wallet) external view returns (uint256 steamId);
    
    /**
     * @notice Get the wallet address for a given Steam ID
     * @param steamId The Steam ID to query
     * @return wallet The wallet address associated with this Steam ID (address(0) if none)
     */
    function getWalletBySteamId(uint256 steamId) external view returns (address wallet);
}