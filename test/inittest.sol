// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { GameWallet } from "../src/GameWallet.sol";

import { ERC20 } from "@openzeppelin/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/access/Ownable.sol";
import { ERC20Permit } from "@openzeppelin/token/ERC20/extensions/ERC20Permit.sol";
import { PRBTest } from "@prb/test/PRBTest.sol";

// --- Adjacent Contracts ---
contract Money is ERC20, Ownable, ERC20Permit {
    constructor() ERC20("MONEY", "MONEY") Ownable(msg.sender) ERC20Permit("MONEY") { }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}

// --- GameWallet with extra convenience testing functions ---
contract GameStakingExtra is GameWallet {
    uint256 public latestPooledNonceUsed;
    Money public money;

    constructor(
        address _token,
        uint256 _max_balance,
        uint256 _withdrawal_delay
    )
        GameWallet(_token, _max_balance, _withdrawal_delay)
    {
        money = Money(_token);
    }

    // incroporate extra convenience or shortcut functions needed for testing here
    // do not use this directly, use addWalletBalance(player, amount) instead
    // which adds money to gs when adding a balance to player
    function setBalance(address user, uint256 amount) external {
        balances[user] = amount;
    }

    function setNonceExpiry(uint256 nonce, uint256 expiry) external {
        noncePool[nonce] = expiry;
    }

    // allows tests to track which nonces are used/unsued
    function setLatestPooledNonceUsed(uint256 nonce) external {
        latestPooledNonceUsed = nonce;
    }
}

// --- User/Persona Testing Interfaces ---
contract Admin {
    GameStakingExtra public gs;

    constructor(address _token, uint256 _max_balance, uint256 _withdrawal_delay) {
        gs = new GameStakingExtra(_token, _max_balance, _withdrawal_delay);
    }

    // Admin Callable Functions
    function grantRole(bytes32 role, address account) public {
        gs.grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) public {
        gs.revokeRole(role, account);
    }

    // Admin Convenience Functions
    // ...
}

contract Submitter {
    Money public money;
    GameStakingExtra public gs;

    constructor(Money _money, GameStakingExtra _gs) {
        money = _money;
        gs = _gs;
    }

    // Submitter Callable Functions
    function executePermit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external
    {
        money.permit(owner, spender, value, deadline, v, r, s);
    }

    function depositTokenAdmin(GameWallet.Deposit memory deposit, GameWallet.Signature memory signedMsg) external {
        gs.depositTokenAdmin(deposit, signedMsg);
    }

    function withdrawTokenAdmin(GameWallet.Withdraw memory withdraw, GameWallet.Signature memory signedMsg) external {
        gs.withdrawTokenAdmin(withdraw, signedMsg);
    }

    function processStakedMatch(
        GameWallet.Stake memory stake1,
        GameWallet.Stake memory stake2,
        GameWallet.Signature memory signedMsg1,
        GameWallet.Signature memory signedMsg2,
        uint256 matchId,
        address winner
    )
        external
    {
        gs.processStakedMatch(stake1, stake2, signedMsg1, signedMsg2, matchId, winner);
    }

    function resetNonceExpiry(uint256 nonce) external {
        gs.resetNonceExpiry(nonce);
    }

    // Submitter Convenience Functions
    // ...
}

contract Player {
    Money public money;
    GameStakingExtra public gs;

    constructor(Money _money, GameStakingExtra _gs) {
        money = _money;
        gs = _gs;
    }

    // Player Callable Functions
    function depositToken(uint256 amount) external {
        gs.depositToken(amount);
    }

    function initiateWithdrawal() external {
        gs.initiateWithdrawal();
    }

    function withdrawToken() external {
        gs.withdrawToken();
    }

    // Player Convenience Functions
    function approveGSMax() external {
        address token_addr = address(gs.token());
        IERC20(token_addr).approve(address(gs), type(uint256).max);
    }
}

contract SigUtils {
    bytes32 internal ERC20_DOMAIN_SEPARATOR;
    bytes32 internal GS_DOMAIN_SEPARATOR;

    constructor(bytes32 _ERC20_DOMAIN_SEPARATOR, bytes32 _GS_DOMAIN_SEPARATOR) {
        ERC20_DOMAIN_SEPARATOR = _ERC20_DOMAIN_SEPARATOR;
        GS_DOMAIN_SEPARATOR = _GS_DOMAIN_SEPARATOR;
    }

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    bytes32 public constant DEPOSIT_TYPEHASH =
        keccak256("Deposit(address user,uint256 nonce,uint256 expiry,uint256 amount,uint256 fee)");
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address user,uint256 nonce,uint256 expiry,uint256 fee)");
    bytes32 public constant STAKE_TYPEHASH =
        keccak256("Stake(address user,uint256 nonce,uint256 expiry,uint256 amount,uint256 fee)");

    // struct Permit {
    //     address owner,
    //     address spender,
    //     uint256 value,
    //     uint256 nonce,
    //     uint256 deadline
    // }

    // struct Deposit {
    //     address user;
    //     uint256 nonce;
    //     uint256 expiry;
    //     uint256 amount;
    //     uint256 fee;
    // }

    // struct Withdraw {
    //     address user;
    //     uint256 nonce;
    //     uint256 expiry;
    //     uint256 fee;
    // }

    // struct Stake {
    //     address user;
    //     uint256 nonce;
    //     uint256 expiry;
    //     uint256 amount;
    //     uint256 fee;
    // }

    // struct Signature {
    //     uint8 v;
    //     bytes32 r;
    //     bytes32 s;
    // }

    // computes the hash of a permit
    function getPermitStructHash(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
    }

    // computes the hash of a deposit
    function getDepositStructHash(GameWallet.Deposit memory _deposit) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(DEPOSIT_TYPEHASH, _deposit.user, _deposit.nonce, _deposit.expiry, _deposit.amount, _deposit.fee)
        );
    }

    // computes the hash of a withdraw
    function getWithdrawStructHash(GameWallet.Withdraw memory _withdraw) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(WITHDRAW_TYPEHASH, _withdraw.user, _withdraw.nonce, _withdraw.expiry, _withdraw.fee));
    }

    // computes the hash of a stake
    function getStakeStructHash(GameWallet.Stake memory _stake) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(STAKE_TYPEHASH, _stake.user, _stake.nonce, _stake.expiry, _stake.amount, _stake.fee));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getPermitTypedDataHash(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline
    )
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", ERC20_DOMAIN_SEPARATOR, getPermitStructHash(owner, spender, value, nonce, deadline)
            )
        );
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getDepositTypedDataHash(GameWallet.Deposit memory _deposit) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", GS_DOMAIN_SEPARATOR, getDepositStructHash(_deposit)));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getWithdrawTypedDataHash(GameWallet.Withdraw memory _withdraw) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", GS_DOMAIN_SEPARATOR, getWithdrawStructHash(_withdraw)));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getStakeTypedDataHash(GameWallet.Stake memory _stake) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", GS_DOMAIN_SEPARATOR, getStakeStructHash(_stake)));
    }
}

/* solhint-disable max-states-count */
contract InitSetup is PRBTest {
    Money public money;
    address public money_addr;

    GameStakingExtra public gs;
    address public gs_addr;

    Admin public admin;
    address public admin_addr;

    Submitter public submitter;
    address public submitter_addr;

    Player public player1;
    address public player1_addr;
    Player public player2;
    address public player2_addr;

    SigUtils internal sigUtils;
    uint256 internal player3PrivateKey;
    uint256 internal player4PrivateKey;
    address internal player3_addr;
    address internal player4_addr;

    uint256 public T0 = 1_685_577_600;

    function wad(uint256 amount) public pure returns (uint256) {
        return (amount * (10 ** 18));
    }

    function addWalletBalance(address player, uint256 amount) public {
        gs.setBalance(player, amount);
        money.mint(gs_addr, amount);
    }

    function setUp() public virtual {
        money = new Money(); // owner is Testing Setup contract
        money_addr = address(money);

        // setup admin and game staking
        // Admin contract deploys game staking and becomes owner after being granted ADMIN role
        admin = new Admin(address(money), wad(1000), 3 hours);
        admin_addr = address(admin);

        gs = admin.gs();
        gs_addr = address(gs);

        submitter = new Submitter(money, admin.gs());
        submitter_addr = address(submitter);
        // submitter does not have TXN_SUBMITTER_ROLE

        player1 = new Player(money, admin.gs());
        player1_addr = address(player1);
        player2 = new Player(money, admin.gs());
        player2_addr = address(player2);

        sigUtils = new SigUtils(money.DOMAIN_SEPARATOR(), gs.DOMAIN_SEPARATOR());
        player3PrivateKey = 0xA11CE;
        player4PrivateKey = 0xB0B;
        player3_addr = vm.addr(player3PrivateKey);
        player4_addr = vm.addr(player4PrivateKey);
    }
}
/* solhint-enable max-states-count */
