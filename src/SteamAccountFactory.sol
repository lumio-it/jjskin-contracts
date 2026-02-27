// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import "@thirdweb-dev/contracts/prebuilts/account/utils/BaseAccountFactory.sol";
import "@thirdweb-dev/contracts/prebuilts/account/non-upgradeable/Account.sol";
import "@thirdweb-dev/contracts/external-deps/openzeppelin/proxy/Clones.sol";
import "@thirdweb-dev/contracts/external-deps/openzeppelin/utils/structs/EnumerableSet.sol";
import "@thirdweb-dev/contracts/extension/upgradeable/PermissionsEnumerable.sol";
import "@thirdweb-dev/contracts/extension/upgradeable/ContractMetadata.sol";

/**
 * @title SteamAccountFactory
 * @author JJSKIN
 * @notice Factory contract for creating deterministic smart wallets based on Steam ID
 * @dev Creates standard Thirdweb ERC-4337 accounts with deterministic addresses using Steam ID as salt
 *      The factory maintains the Steam ID ↔ Wallet mapping, accounts themselves are standard Thirdweb accounts
 */
contract SteamAccountFactory is BaseAccountFactory, ContractMetadata, PermissionsEnumerable {
    using EnumerableSet for EnumerableSet.AddressSet;
    
    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Mapping from wallet address to Steam ID
    mapping(address => uint256) public walletToSteamId;
    
    /// @notice Mapping from Steam ID to wallet address  
    mapping(uint256 => address) public steamIdToWallet;
    
    /// @notice Mapping to check if a Steam ID has been registered
    mapping(uint256 => bool) public isSteamIdRegistered;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Emitted when a new account is created with Steam ID
    event AccountCreatedWithSteamId(
        address indexed account, 
        address indexed accountAdmin, 
        uint256 indexed steamId
    );

    /*//////////////////////////////////////////////////////////////
                               ERRORS
    //////////////////////////////////////////////////////////////*/
    
    /// @notice Thrown when trying to create account for already registered Steam ID
    error SteamIdAlreadyRegistered(uint256 steamId, address existingWallet);
    
    /// @notice Thrown when Steam ID is invalid (must be non-zero)
    error InvalidSteamId();

    /*//////////////////////////////////////////////////////////////
                            CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    
    constructor(
        address _defaultAdmin,
        IEntryPoint _entrypoint
    ) BaseAccountFactory(
        address(new Account(_entrypoint, address(this))),
        address(_entrypoint)
    ) {
        _setupRole(DEFAULT_ADMIN_ROLE, _defaultAdmin);
    }

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Overrides the base createAccount function to create a smart wallet tied to a Steam ID
     * @dev The Steam ID is passed via the _data parameter
     * @param _admin The admin of the new account (the user's in-app wallet)
     * @param _data The ABI-encoded Steam ID
     * @return account The address of the created account
     */
    function createAccount(
        address _admin,
        bytes calldata _data
    ) external override returns (address account) {
        // Decode the Steam ID from the _data parameter
        uint256 steamId = _data.length >= 32 ? abi.decode(_data, (uint256)) : 0;

        // Validation
        if (steamId == 0) revert InvalidSteamId();
        
        // Check if Steam ID is already registered
        if (isSteamIdRegistered[steamId]) {
            address existingWallet = steamIdToWallet[steamId];
            // If wallet already exists for this Steam ID, return it
            if (existingWallet != address(0)) {
                return existingWallet;
            }
        }

        // Generate salt and check if account already exists
        bytes32 salt = _generateSalt(_admin, _data);
        address predicted = Clones.predictDeterministicAddress(accountImplementation, salt);
        
        // If account already exists at predicted address, just set up mappings
        if (predicted.code.length > 0) {
            account = predicted;
            // Set up mappings if not already done
            if (walletToSteamId[account] == 0) {
                walletToSteamId[account] = steamId;
                steamIdToWallet[steamId] = account;
                isSteamIdRegistered[steamId] = true;
                emit AccountCreatedWithSteamId(account, _admin, steamId);
            }
            return account;
        }

        // Deploy new account
        account = Clones.cloneDeterministic(accountImplementation, salt);
        
        // Initialize the account
        _initializeAccount(account, _admin, _data);
        
        // Emit standard event
        emit AccountCreated(account, _admin);

        // Store the Steam ID mapping
        walletToSteamId[account] = steamId;
        steamIdToWallet[steamId] = account;
        isSteamIdRegistered[steamId] = true;

        emit AccountCreatedWithSteamId(account, _admin, steamId);
        
        return account;
    }

    /**
     * @notice Get the wallet address for a given Steam ID
     * @param _steamId The Steam ID to query
     * @return wallet The wallet address associated with this Steam ID (address(0) if none)
     */
    function getWalletBySteamId(uint256 _steamId) external view returns (address wallet) {
        wallet = steamIdToWallet[_steamId];
    }
    
    /**
     * @notice Get the Steam ID for a given wallet address
     * @param _wallet The wallet address to query
     * @return steamId The Steam ID associated with this wallet (0 if none)
     */
    function getSteamIdByWallet(address _wallet) external view returns (uint256 steamId) {
        steamId = walletToSteamId[_wallet];
    }
    
    /**
     * @notice Check if a Steam ID has been registered
     * @param _steamId The Steam ID to check
     * @return registered True if the Steam ID has been registered
     */
    function isSteamIdRegisteredCheck(uint256 _steamId) external view returns (bool registered) {
        registered = isSteamIdRegistered[_steamId];
    }
    
    /**
     * @notice Predict the address of a smart wallet for a given Steam ID
     * @dev This allows checking what address would be generated without deploying
     * @param _admin The admin address
     * @param _steamId The Steam ID
     * @return predicted The predicted address
     */
    function getAddressForSteamId(
        address _admin,
        uint256 _steamId
    ) external view returns (address predicted) {
        bytes memory data = abi.encode(_steamId);
        bytes32 salt = _generateSalt(_admin, data);
        predicted = Clones.predictDeterministicAddress(accountImplementation, salt);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Override the account initialization
     * @dev This is called when deploying a new account
     */
    function _initializeAccount(
        address _account,
        address _admin,
        bytes calldata /* _data */
    ) internal virtual override {
        // Initialize the account with empty data since we don't need to store Steam ID in the account
        Account(payable(_account)).initialize(_admin, "");
        
        // The Steam ID mapping is handled in createAccount
    }
    
    /**
     * @notice Generate salt for deterministic deployment based on Steam ID
     * @dev This ensures the same Steam ID always generates the same wallet address
     * @param _data The encoded data containing Steam ID
     * @return salt The generated salt
     */
    function _generateSalt(
        address /* _admin */,
        bytes memory _data
    ) internal pure virtual override returns (bytes32 salt) {
        // Decode Steam ID from data
        uint256 steamId = _data.length >= 32 ? abi.decode(_data, (uint256)) : 0;
        
        // Generate deterministic salt from Steam ID only
        // This ensures unique addresses per Steam ID regardless of admin
        salt = keccak256(abi.encodePacked(steamId, "JJSKIN_STEAM_WALLET_V2"));
    }

    /**
     * @notice Returns whether contract metadata can be set in the given execution context.
     * @dev Required override for ContractMetadata extension
     */
    function _canSetContractURI() internal view virtual override returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice Override to verify accounts created by this factory
     * @dev We check if the account code matches our implementation's clone
     */
    function _isAccountOfFactory(address _account, bytes32 /* _salt */) internal view virtual override returns (bool) {
        // During creation, the account won't be in our mappings yet
        // So we check if it's a clone of our implementation
        if (_account.code.length == 0) return false;
        
        // Check if this is a clone of our account implementation
        address impl = _getImplementation(_account);
        return impl == accountImplementation;
    }

    /**
     * @notice Returns the sender in the given execution context.
     * @dev Required override for Multicall and Permissions extensions
     */
    function _msgSender() internal view override(Multicall, Permissions) returns (address) {
        return msg.sender;
    }
}