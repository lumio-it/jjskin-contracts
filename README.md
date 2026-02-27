# JJSKIN Smart Contracts

Solidity smart contracts for the [JJSKIN](https://jjskin.com) CS2 skin marketplace. Trustless escrow trading with USDC on Arbitrum One.

## Deployed Contracts (Arbitrum One)

| Contract | Address | Verified |
|----------|---------|----------|
| **JJSKIN** | [`0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7`](https://arbiscan.io/address/0x966F2BBF404B36d6E30f226838e772AfcbE6Dcf7) | Yes |
| **SteamAccountFactory** | [`0xF20d6e714cd03Dbc1f03A4c1117697cE60F55405`](https://arbiscan.io/address/0xF20d6e714cd03Dbc1f03A4c1117697cE60F55405) | Yes |
| **DcapAttestationVerifier** | [`0x4D455ceA16E65c7566105caDEAd68851625BD8a9`](https://arbiscan.io/address/0x4D455ceA16E65c7566105caDEAd68851625BD8a9) | Yes |

**External dependencies:**
- USDC: [`0xaf88d065e77c8cC2239327C5EDb3A432268e5831`](https://arbiscan.io/address/0xaf88d065e77c8cC2239327C5EDb3A432268e5831) (Native USDC on Arbitrum One)
- EntryPoint: [`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`](https://arbiscan.io/address/0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789) (ERC-4337 v0.6)

## Overview

JJSKIN is a trustless CS2 skin marketplace where:

- **Sellers** sign EIP-712 listings off-chain (zero gas to list)
- **Buyers** purchase on-chain, locking USDC in escrow
- **Oracle** verifies Steam trade completion via [TLSNotary](https://tlsnotary.org) proofs running inside an [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) confidential VM
- Funds are released to the seller or refunded to the buyer based on cryptographic proof

No one — not even the JJSKIN team — can access escrowed funds. The oracle's private key lives in encrypted TDX memory and is never exposed.

## Contracts

| Contract | Purpose |
|----------|---------|
| `JJSKIN.sol` | Core marketplace: listings, purchases, escrow, settlement, buy orders |
| `SteamAccountFactory.sol` | Links Steam accounts to wallets via ERC-4337 smart accounts |
| `DcapAttestationVerifier.sol` | Verifies Intel TDX DCAP quotes for oracle registration |
| `CS2AaveVault.sol` | ERC-4626 yield vault for idle escrow funds (Aave) |

## Build & Test

Requires [Foundry](https://book.getfoundry.sh/getting-started/installation).

```bash
# Install dependencies
forge install

# Build
forge build

# Run all tests
forge test

# Gas report
forge test --gas-report

# Coverage
forge coverage
```

## Architecture

```
src/
  JJSKIN.sol                    # Core marketplace (escrow, settlement, buy orders)
  SteamAccountFactory.sol       # Steam ID <-> wallet mapping (ERC-4337)
  DcapAttestationVerifier.sol   # TDX DCAP quote verification
  CS2AaveVault.sol              # ERC-4626 yield vault
  interfaces/                   # Contract interfaces
  libraries/                    # Shared libraries
  mocks/                        # Test mocks (MockUSDC, MockAave)

test/
  CS2MarketplaceV2.t.sol                # Core functionality
  CS2MarketplaceV2Comprehensive.t.sol   # Full flow tests
  CS2MarketplaceV2Security.t.sol        # Security tests
  CS2AaveVault.t.sol                    # Vault tests
  fuzz/                                 # Fuzz tests
  invariant/                            # Invariant tests
  unit/                                 # Unit tests

script/
  DeployMainnet.s.sol           # Arbitrum One deployment
  DeployTestnet.s.sol           # Arbitrum Sepolia deployment
  DeployLocal.s.sol             # Local Anvil deployment
```

## Key Design Decisions

- **Off-chain signatures**: Sellers sign EIP-712 listings off-chain — only the buyer's purchase goes on-chain (saves 50%+ gas)
- **Single-slot structs**: `Purchase` fits in 1 storage slot (26 bytes) — saves ~20,000 gas per trade
- **Batch settlement**: `batchReleaseFunds()` skips invalid trades instead of reverting (idempotent, safe to retry)
- **Oracle trust model**: Oracle decisions are final, but backed by TLSNotary cryptographic proofs stored on Arweave for public audit
- **0.5% fee**: Platform fee capped at 5% max (`MAX_FEE_PERCENT = 500` basis points), currently set to 0.5%

## Trading Fee

**0.5%** — possibly the lowest in the CS2 skin market. Gas fees are sponsored by JJSKIN.

## Security

- `Ownable2Step` — two-step ownership transfer
- `ReentrancyGuardTransient` — reentrancy protection using EIP-1153 transient storage
- `SafeERC20` — safe token transfers
- `Pausable` — emergency pause
- 26 custom errors for gas-efficient reverts
- Fuzz tests, invariant tests, and mutation testing (94% kill rate)

## License

MIT

## Links

- **App**: [jjskin.com](https://jjskin.com)
- **Docs**: [docs.jjskin.com](https://docs.jjskin.com)
- **GitHub**: [github.com/lumio-it](https://github.com/lumio-it)
