// SPDX-License-Identifier: MIT
pragma solidity 0.8.33;

import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IPool {
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external;

    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external returns (uint256);
}

interface IAToken is IERC20 {
    function UNDERLYING_ASSET_ADDRESS() external view returns (address);
    function scaledBalanceOf(address user) external view returns (uint256);
    function getScaledUserBalanceAndSupply(address user) external view returns (uint256, uint256);
}

/**
 * @title CS2AaveVault
 * @notice ERC-4626 vault wrapper for Aave V3 USDC lending
 * @dev Implements the ERC-4626 standard for tokenized vaults
 * @custom:security-contact security@jjskin.com
 */
contract CS2AaveVault is ERC4626, Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Math for uint256;

    // ========== State Variables ==========
    
    IPool public immutable aavePool;
    IAToken public immutable aToken;
    address public immutable marketplace;
    
    // Buffer configuration (basis points, 1000 = 10%)
    uint256 public bufferBasisPoints = 1000;
    uint256 public constant MAX_BUFFER_BPS = 5000; // Max 50% buffer
    uint256 public constant BPS_DENOMINATOR = 10000;
    
    // Emergency withdrawal
    bool public emergencyMode = false;
    
    // Track total deposits for yield calculation
    uint256 public totalDeposited;
    
    // ========== Events ==========
    
    event BufferUpdated(uint256 oldBuffer, uint256 newBuffer);
    event EmergencyModeActivated(address indexed activator);
    event EmergencyModeDeactivated(address indexed deactivator);
    event YieldHarvested(uint256 amount, address indexed recipient);
    
    // ========== Errors ==========
    
    error InvalidBuffer();
    error Unauthorized();
    error EmergencyModeActive();
    error InvalidAddress();
    error InsufficientLiquidity();
    
    // ========== Constructor ==========
    
    /**
     * @notice Initialize the vault
     * @param _asset USDC token address
     * @param _aavePool Aave V3 pool address
     * @param _aToken Aave aUSDC token address
     * @param _marketplace CS2Marketplace address (privileged depositor)
     */
    constructor(
        IERC20 _asset,
        IPool _aavePool,
        IAToken _aToken,
        address _marketplace,
        address _owner
    ) ERC4626(_asset) ERC20("CS2 Aave USDC Vault", "cs2AaveUSDC") Ownable(_owner) {
        if (address(_asset) == address(0) || 
            address(_aavePool) == address(0) || 
            address(_aToken) == address(0) || 
            _marketplace == address(0)) {
            revert InvalidAddress();
        }
        
        aavePool = _aavePool;
        aToken = _aToken;
        marketplace = _marketplace;
        
        // Verify aToken matches asset
        if (_aToken.UNDERLYING_ASSET_ADDRESS() != address(_asset)) {
            revert InvalidAddress();
        }
        
        // Approve Aave pool for deposits
        _asset.forceApprove(address(_aavePool), type(uint256).max);
    }
    
    // ========== View Functions ==========
    
    /**
     * @notice Total assets managed by the vault
     * @return Total USDC value including that deposited in Aave
     */
    function totalAssets() public view virtual override returns (uint256) {
        if (emergencyMode) {
            // In emergency mode, only count liquid USDC
            return IERC20(asset()).balanceOf(address(this));
        }
        
        // Total = USDC in vault + aUSDC balance (which represents USDC + yield in Aave)
        uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
        uint256 aaveBalance = aToken.balanceOf(address(this));
        
        return liquidBalance + aaveBalance;
    }
    
    /**
     * @notice Calculate optimal buffer based on recent activity
     * @dev Can be overridden for more sophisticated calculations
     */
    function getOptimalBuffer() public view virtual returns (uint256) {
        uint256 total = totalAssets();
        return total.mulDiv(bufferBasisPoints, BPS_DENOMINATOR);
    }
    
    /**
     * @notice Check if rebalancing is needed
     */
    function needsRebalance() public view returns (bool) {
        uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
        uint256 optimalBuffer = getOptimalBuffer();
        
        // Rebalance if we have 2x the buffer or less than 0.5x
        return liquidBalance > optimalBuffer * 2 || 
               (liquidBalance < optimalBuffer / 2 && aToken.balanceOf(address(this)) > 0);
    }
    
    // ========== Deposit/Withdraw Overrides ==========
    
    /**
     * @notice Deposit assets and receive shares
     * @dev Automatically deposits excess to Aave
     */
    function deposit(uint256 assets, address receiver) 
        public 
        virtual 
        override 
        nonReentrant 
        returns (uint256) 
    {
        if (emergencyMode) revert EmergencyModeActive();
        
        uint256 shares = super.deposit(assets, receiver);
        totalDeposited += assets; // Track deposits
        
        // Rebalance after deposit if needed
        _rebalanceIfNeeded();
        
        return shares;
    }
    
    /**
     * @notice Mint shares by depositing assets
     * @dev Automatically deposits excess to Aave
     */
    function mint(uint256 shares, address receiver) 
        public 
        virtual 
        override 
        nonReentrant 
        returns (uint256) 
    {
        if (emergencyMode) revert EmergencyModeActive();
        
        uint256 assets = super.mint(shares, receiver);
        totalDeposited += assets; // Track deposits
        
        // Rebalance after deposit if needed
        _rebalanceIfNeeded();
        
        return assets;
    }
    
    /**
     * @notice Withdraw assets by burning shares
     * @dev Automatically withdraws from Aave if needed
     */
    function withdraw(
        uint256 assets,
        address receiver,
        address owner
    ) public virtual override nonReentrant returns (uint256) {
        // Check liquid balance
        uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
        
        // If insufficient liquid balance, withdraw from Aave
        if (liquidBalance < assets && !emergencyMode) {
            uint256 toWithdraw = assets - liquidBalance;
            _withdrawFromAave(toWithdraw);
        }
        
        uint256 shares = super.withdraw(assets, receiver, owner);
        
        // Reduce totalDeposited proportionally
        uint256 totalAssetsBefore = totalAssets() + assets; // Add back withdrawn amount
        if (totalAssetsBefore > 0 && totalDeposited > 0) {
            uint256 depositReduction = totalDeposited.mulDiv(assets, totalAssetsBefore);
            totalDeposited = totalDeposited > depositReduction ? totalDeposited - depositReduction : 0;
        }
        
        return shares;
    }
    
    /**
     * @notice Redeem shares for assets
     * @dev Automatically withdraws from Aave if needed
     */
    function redeem(
        uint256 shares,
        address receiver,
        address owner
    ) public virtual override nonReentrant returns (uint256) {
        // Calculate assets needed
        uint256 assets = convertToAssets(shares);
        uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
        
        // If insufficient liquid balance, withdraw from Aave
        if (liquidBalance < assets && !emergencyMode) {
            uint256 toWithdraw = assets - liquidBalance;
            _withdrawFromAave(toWithdraw);
        }
        
        uint256 assetsRedeemed = super.redeem(shares, receiver, owner);
        
        // Reduce totalDeposited proportionally
        uint256 totalAssetsBefore = totalAssets() + assetsRedeemed; // Add back redeemed amount
        if (totalAssetsBefore > 0 && totalDeposited > 0) {
            uint256 depositReduction = totalDeposited.mulDiv(assetsRedeemed, totalAssetsBefore);
            totalDeposited = totalDeposited > depositReduction ? totalDeposited - depositReduction : 0;
        }
        
        return assetsRedeemed;
    }
    
    // ========== Internal Functions ==========
    
    /**
     * @notice Deposit excess USDC to Aave
     */
    function _depositToAave(uint256 amount) internal {
        if (amount == 0) return;
        
        IERC20 _asset = IERC20(asset());
        uint256 balance = _asset.balanceOf(address(this));
        
        if (balance < amount) {
            amount = balance;
        }
        
        if (amount > 0) {
            aavePool.supply(address(_asset), amount, address(this), 0);
        }
    }
    
    /**
     * @notice Withdraw USDC from Aave
     */
    function _withdrawFromAave(uint256 amount) internal {
        if (amount == 0) return;
        
        uint256 aaveBalance = aToken.balanceOf(address(this));
        if (aaveBalance < amount) {
            amount = aaveBalance;
        }
        
        if (amount > 0) {
            aavePool.withdraw(address(asset()), amount, address(this));
        }
    }
    
    /**
     * @notice Rebalance between liquid and Aave if needed
     */
    function _rebalanceIfNeeded() internal {
        uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
        uint256 optimalBuffer = getOptimalBuffer();
        
        if (liquidBalance > optimalBuffer * 2) {
            // Too much liquid, deposit excess to Aave
            uint256 excess = liquidBalance - optimalBuffer;
            _depositToAave(excess);
        } else if (liquidBalance < optimalBuffer / 2 && aToken.balanceOf(address(this)) > 0) {
            // Too little liquid, withdraw from Aave
            uint256 needed = optimalBuffer - liquidBalance;
            _withdrawFromAave(needed);
        }
    }
    
    // ========== Admin Functions ==========
    
    /**
     * @notice Update buffer size
     * @param newBufferBps New buffer in basis points
     */
    function setBuffer(uint256 newBufferBps) external onlyOwner {
        if (newBufferBps > MAX_BUFFER_BPS) revert InvalidBuffer();
        
        uint256 oldBuffer = bufferBasisPoints;
        bufferBasisPoints = newBufferBps;
        
        emit BufferUpdated(oldBuffer, newBufferBps);
        
        // Rebalance with new buffer
        _rebalanceIfNeeded();
    }
    
    /**
     * @notice Force a rebalance
     */
    function rebalance() external {
        if (msg.sender != owner() && msg.sender != marketplace) {
            revert Unauthorized();
        }
        _rebalanceIfNeeded();
    }
    
    /**
     * @notice Harvest yield for platform
     * @dev Only callable by marketplace or owner
     * @param recipient Address to receive harvested yield
     */
    function harvestYield(address recipient) external returns (uint256 yield) {
        if (msg.sender != marketplace && msg.sender != owner()) {
            revert Unauthorized();
        }
        
        // Calculate total yield earned
        uint256 totalValue = totalAssets();
        
        // Yield is the difference between current assets and total deposited
        if (totalValue > totalDeposited) {
            yield = totalValue - totalDeposited;
            
            // Withdraw yield from Aave if needed
            uint256 liquidBalance = IERC20(asset()).balanceOf(address(this));
            if (liquidBalance < yield) {
                _withdrawFromAave(yield - liquidBalance);
            }
            
            // Transfer yield to recipient
            IERC20(asset()).safeTransfer(recipient, yield);
            
            // Don't reduce totalDeposited - we're only harvesting the yield
            // totalDeposited remains the same to track principal
            
            emit YieldHarvested(yield, recipient);
        }
    }
    
    /**
     * @notice Emergency withdrawal - pull all funds from Aave
     * @dev Only owner can activate
     */
    function activateEmergencyMode() external onlyOwner {
        emergencyMode = true;
        
        // Withdraw everything from Aave
        uint256 aaveBalance = aToken.balanceOf(address(this));
        if (aaveBalance > 0) {
            aavePool.withdraw(address(asset()), type(uint256).max, address(this));
        }
        
        emit EmergencyModeActivated(msg.sender);
    }
    
    /**
     * @notice Deactivate emergency mode and resume normal operations
     */
    function deactivateEmergencyMode() external onlyOwner {
        emergencyMode = false;
        
        // Rebalance funds
        _rebalanceIfNeeded();
        
        emit EmergencyModeDeactivated(msg.sender);
    }
    
    // ========== Max Deposit/Mint Overrides ==========
    
    /**
     * @notice Maximum deposit allowed
     */
    function maxDeposit(address) public view virtual override returns (uint256) {
        return emergencyMode ? 0 : type(uint256).max;
    }
    
    /**
     * @notice Maximum mint allowed
     */
    function maxMint(address) public view virtual override returns (uint256) {
        return emergencyMode ? 0 : type(uint256).max;
    }
}