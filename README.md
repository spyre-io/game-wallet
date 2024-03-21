# Game Wallet

Game Wallet allows players to deposit a token balance and thereafter use signed messages to allow a server to handle all aspects of match settlement and submitting transactions to a blockchain network.

## Design

Owner of the Game Wallet can on-board one (or more) admins to manage settlement of transactions.

An admin is responsible for determining the winner among two players and submit the transaction to debit one player and credit the other player. Admin can also collect a processing fee to cover gas and other infra costs. Admin role can be automated using a reference server implementation in this repo.

Players would have to spend gas to deposit a token balance (ex: USDC) into the Game Wallet. After deposit, they only sign messages (EIP-712 type support) for the amount they are about to stake while entering a match and do not have to submit transactions themselves to the network.

## Deployment and Setup

Build the project

```bash
forge clean && forge build
```

Deploy Game Wallet contract for a particular token. Ex: USDC

```bash
forge create --private-key <your-private-key> --rpc-url <network-rpc-url> contracts/src/GameStaking.sol:GameStaking --constructor-args <usdc-token-address> $(cast --to-wei 1000) 60 99999
# 1000 - max allowed deposit amount (1000 ETH)
# Please remove the cast command and use a number with 6 decimals for USDC.

# 60 - withdrawal delay (60 seconds)
# This is for testing purposes. Please use ~24 hours for the main deployment.

# 99999 - chain id (BASE SEPOLIA)
# Please use the appropriate chain id for deployment. This is to initialize EIP-712 constants.
```

Grant access role to an admin address which can process player stakes and submit transactions to the network.

```bash
❯ cast send --private-key <your-private-key> --rpc-url <network-rpc-url> <game-wallet-deployment> "grantRole(bytes32,address)" 0xe36dd3d438139416652addc594300757f3bf91ccb298951da2b3fc7876a7ce1d <admin/server-address>

# 0xe36dd3d438139416652addc594300757f3bf91ccb298951da2b3fc7876a7ce1d
# Bytes32 value of the TXN_SUBMITTER_ROLE role which admins would need to process transactions on behalf of players.
```
