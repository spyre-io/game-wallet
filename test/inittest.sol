// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { GameStaking } from "../src/GameStaking.sol";

import { ERC20 } from "@openzeppelin/token/ERC20/ERC20.sol";
import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { Ownable } from "@openzeppelin/access/Ownable.sol";

// --- Adjacent Contracts ---
contract Money is ERC20, Ownable {
    constructor() ERC20("MONEY", "MONEY") Ownable(msg.sender) { }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}

// --- GameStaking with extra convenience testing functions ---
contract GameStakingExtra is GameStaking {
    constructor(
        address _token,
        uint256 _max_balance,
        uint256 _withdrawal_delay
    )
        GameStaking(_token, _max_balance, _withdrawal_delay)
    { }

    // incroporate extra convenience or shortcut functions needed for testing here
    function setBalance(address user, uint256 amount) external {
        balances[user] = amount;
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
    GameStakingExtra public gs;

    constructor(GameStakingExtra _gs) {
        gs = _gs;
    }

    // Submitter Callable Functions
    function withdrawTokenAdmin(
        GameStaking.Withdraw memory withdraw,
        GameStaking.Signature memory signedMsg
    )
        external
    {
        gs.withdrawTokenAdmin(withdraw, signedMsg);
    }

    function processStakedMatch(
        GameStaking.Stake memory stake1,
        GameStaking.Stake memory stake2,
        GameStaking.Signature memory signedMsg1,
        GameStaking.Signature memory signedMsg2,
        uint256 matchId,
        address winner
    )
        external
    {
        gs.processStakedMatch(stake1, stake2, signedMsg1, signedMsg2, matchId, winner);
    }

    function processExpiredMessage(
        GameStaking.Stake memory stake,
        GameStaking.Signature memory signedMsg,
        bool chargeFee
    )
        external
    {
        gs.processExpiredMessage(stake, signedMsg, chargeFee);
    }

    // Submitter Convenience Functions
    // ...
}

contract Player {
    GameStakingExtra public gs;

    constructor(GameStakingExtra _gs) {
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
    bytes32 internal DOMAIN_SEPARATOR;

    constructor(bytes32 _DOMAIN_SEPARATOR) {
        DOMAIN_SEPARATOR = _DOMAIN_SEPARATOR;
    }

    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address user,uint256 nonce,uint256 expiry,uint256 fee)");
    bytes32 public constant STAKE_TYPEHASH =
        keccak256("Stake(address user,uint256 nonce,uint256 expiry,uint256 amount,uint256 fee)");

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

    // computes the hash of a withdraw
    function getWithdrawStructHash(GameStaking.Withdraw memory _withdraw) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(WITHDRAW_TYPEHASH, _withdraw.user, _withdraw.nonce, _withdraw.expiry, _withdraw.fee));
    }

    // computes the hash of a stake
    function getStakeStructHash(GameStaking.Stake memory _stake) internal pure returns (bytes32) {
        return
            keccak256(abi.encode(STAKE_TYPEHASH, _stake.user, _stake.nonce, _stake.expiry, _stake.amount, _stake.fee));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getWithdrawTypedDataHash(GameStaking.Withdraw memory _withdraw) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, getWithdrawStructHash(_withdraw)));
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getStakeTypedDataHash(GameStaking.Stake memory _stake) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, getStakeStructHash(_stake)));
    }
}

/* solhint-disable max-states-count */
contract InitSetup {
    Money public money;

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

    uint256 public T0 = 1_685_577_600;

    function wad(uint256 amount) public pure returns (uint256) {
        return (amount * (10 ** 18));
    }

    function setUp() public virtual {
        money = new Money(); // owner is Testing Setup contract

        // setup admin and game staking
        // Admin contract deploys game staking and becomes owner after being granted ADMIN role
        admin = new Admin(address(money), wad(1000), 3 hours);
        admin_addr = address(admin);

        gs = admin.gs();
        gs_addr = address(gs);

        submitter = new Submitter(admin.gs());
        submitter_addr = address(submitter);
        // submitter does not have TXN_SUBMITTER_ROLE

        player1 = new Player(admin.gs());
        player1_addr = address(player1);
        player2 = new Player(admin.gs());
        player2_addr = address(player2);
    }
}
/* solhint-enable max-states-count */
