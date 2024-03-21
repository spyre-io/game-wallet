// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { GameWallet } from "../src/GameWallet.sol";
import { Admin, Submitter, Player, InitSetup, SigUtils } from "./inittest.sol";

// when a user deposits token balance
contract BalancesDepositTest is PRBTest, InitSetup {
    // Available:
    // admin
    // submitter
    // player1
    // player2

    function setUp() public override {
        super.setUp();
        vm.warp(T0);

        // additional setup
        admin.grantRole(gs.TXN_SUBMITTER_ROLE(), submitter_addr); // submitter receives role

        money.mint(player1_addr, wad(10_000)); // money deposited into player1 wallet
    }

    // should fail if final balance would exceed max balance with starting balance zero
    function testFailFinalBalanceExceedsStartZero() public {
        player1.approveGSMax();
        player1.depositToken(wad(2000));
    }

    // should fail if final balance would exceed max balance with starting balance positive
    function testFailFinalBalanceExceedsStartPositive() public {
        // first deposit
        player1.approveGSMax();
        player1.depositToken(wad(250));

        // second deposit exceeds 1000 total
        player1.depositToken(wad(751));
    }

    // should fail if wallet has insufficient balance
    function testFailDepositInsufficientBalance() public {
        money.mint(player2_addr, wad(99));

        player2.approveGSMax();
        player2.depositToken(wad(111));
    }

    // should fail if staking contract does not have user approval
    function testFailGSNoApproval() public {
        money.mint(player2_addr, wad(99));
        player2.depositToken(wad(50));
    }

    // should debit their wallet balance and credit balance in staking contract
    function testBalanceCredit() public {
        player1.approveGSMax();
        player1.depositToken(wad(25));

        assertEq(money.balanceOf(player1_addr), wad(9975));
        assertEq(gs.balances(player1_addr), wad(25));
    }

    // should stop pending withdrawal before the withdrawal delay is complete
    function testResetPendingWithdrawalBeforeDelay() public {
        // deposit
        player1.approveGSMax();
        player1.depositToken(wad(25));

        // start pending withdrawal
        player1.initiateWithdrawal();

        // deposit again before withdrawal delay is complete
        player1.depositToken(wad(25));

        // assert total deposit and withdrawal delay is reset to uintmax
        assertEq(gs.balances(player1_addr), wad(50));
        assertEq(gs.withdrawAfter(player1_addr), type(uint256).max);
    }

    // should stop pending withdrawal after the withdrawal delay is complete
    function testResetPendingWithdrawalAfterDelay() public {
        // deposit
        player1.approveGSMax();
        player1.depositToken(wad(25));

        // start pending withdrawal
        vm.warp(T0 + 1 days);
        player1.initiateWithdrawal();

        // warp time to after
        vm.warp(T0 + 2 days);
        // deposit again after withdrawal delay is complete
        player1.depositToken(wad(25));

        // assert total deposit and withdrawal delay is reset to uintmax
        assertEq(gs.balances(player1_addr), wad(50));
        assertEq(gs.withdrawAfter(player1_addr), type(uint256).max);
    }

    // // should emit BalanceUpdate event
    // function testExample() public { }
}

// when a user self withdraws their token balance
contract BalancesUserWithdrawalTest is PRBTest, InitSetup {
    // Available:
    // admin
    // submitter
    // player1
    // player2

    function setUp() public override {
        super.setUp();
        vm.warp(T0);

        // additional setup
        admin.grantRole(gs.TXN_SUBMITTER_ROLE(), submitter_addr); // submitter receives role

        money.mint(player1_addr, wad(10_000)); // money deposited into player1 wallet
        player1.approveGSMax();
        player1.depositToken(wad(250));
    }

    // should be max_uint by default
    function testDefaultWithdrawAfterTS() public {
        assertEq(gs.withdrawAfter(player1_addr), type(uint256).max);
    }

    // should set withdraw after timestamp and update max_uint
    function testSetWithdrawAfterTS() public {
        player1.initiateWithdrawal();

        // withdrawAfter should be set to 3 hours from T0
        assertEq(gs.withdrawAfter(player1_addr), T0 + 3 hours);
    }

    // should reset withdraw after timestamp if transaction is executed again
    function testResetWithdrawAfterTS() public {
        player1.initiateWithdrawal();
        vm.warp(T0 + 1 days);
        player1.initiateWithdrawal();

        // withdrawAfter should be reset
        assertEq(gs.withdrawAfter(player1_addr), T0 + 1 days + 3 hours);
    }

    // should set when user has no balance
    function testSetWithdrawAfterNoBalance() public {
        player2.initiateWithdrawal();

        // withdrawAfter should be set to 3 hours from T0
        assertEq(gs.withdrawAfter(player2_addr), T0 + 3 hours);
    }

    // should set when user has no balance and reset after deposit
    function testSetWithdrawAfterNoBalanceResetDeposit() public {
        player2.initiateWithdrawal();
        money.mint(player2_addr, wad(10_000)); // money deposited into player1 wallet
        player2.approveGSMax();
        player2.depositToken(wad(250));

        // withdrawAfter should be reset
        assertEq(gs.withdrawAfter(player2_addr), type(uint256).max);
    }

    // should set withdraw after to 0 after withdrawal
    function testSetWithdrawAfterZero() public {
        // initiate withdrawal
        player1.initiateWithdrawal();
        vm.warp(T0 + 4 hours);

        // complete withdrawal
        player1.withdrawToken();

        assertEq(gs.withdrawAfter(player1_addr), 0);
    }

    // should debit full balance and credit user wallet
    function testDebitFullBalance() public {
        // initiate withdrawal
        player1.initiateWithdrawal();
        vm.warp(T0 + 4 hours);

        // complete withdrawal
        player1.withdrawToken();

        assertEq(gs.balances(player1_addr), wad(0));
        assertEq(money.balanceOf(player1_addr), wad(10_000));
    }

    // should fail if withdrawal delay has not been met
    function testFailWithdrawalDelayIncomplete() public {
        // initiate withdrawal
        player1.initiateWithdrawal();
        vm.warp(T0 + 2 hours);

        // fail
        player1.withdrawToken();
    }

    // should fail if withdrawal was not initiated
    function testFailWithdrawalNotInitiated() public {
        player1.withdrawToken();
    }

    // // should emit BalanceUpdate event
    // function testExample() public { }
}

// when a user signs a message to allow server to withdraw their token balance
contract BalancesServerWithdrawalTest is PRBTest, InitSetup {
    // Available:
    // admin
    // submitter
    // player1
    // player2

    SigUtils internal sigUtils;
    uint256 internal player3PrivateKey;
    uint256 internal player4PrivateKey;
    address internal player3_addr;
    address internal player4_addr;

    function setUp() public override {
        super.setUp();
        vm.warp(T0);

        // additional setup
        admin.grantRole(gs.TXN_SUBMITTER_ROLE(), submitter_addr); // submitter receives role

        sigUtils = new SigUtils(gs.DOMAIN_SEPARATOR());
        player3PrivateKey = 0xA11CE;
        player4PrivateKey = 0xB0B;
        player3_addr = vm.addr(player3PrivateKey);
        player4_addr = vm.addr(player4PrivateKey);

        // issue balance with testing shortcut
        gs.setBalance(player3_addr, wad(250)); // ensure player3 has internal gs balance
        money.mint(gs_addr, wad(250)); // ensure GS has money erc20 balance
    }

    // should return true when message is valid
    function testWithdrawSignedMessage() public {
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: 0, expiry: T0 + 1 days, fee: wad(15) });

        bytes32 digest = sigUtils.getWithdrawTypedDataHash(withdraw);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, digest);

        GameWallet.Signature memory sigMsg = GameWallet.Signature({ v: v, r: r, s: s });

        assertEq(gs.withdrawSignedCheck(withdraw, sigMsg), player3_addr);
    }

    // should return false when message is not valid
    function testWithdrawSignedMessageInvalidAddress() public {
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: 0, expiry: T0 + 1 days, fee: wad(15) });

        bytes32 digest = sigUtils.getWithdrawTypedDataHash(withdraw);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, digest);

        GameWallet.Signature memory sigMsg = GameWallet.Signature({ v: v, r: r, s: s });

        assertNotEq(gs.withdrawSignedCheck(withdraw, sigMsg), player4_addr);
    }

    // should succeed if nonce is correct and expiry is correct
    function testWithdrawalServer() public {
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: 0, expiry: T0 + 1 days, fee: wad(15) });

        bytes32 digest = sigUtils.getWithdrawTypedDataHash(withdraw);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, digest);

        GameWallet.Signature memory sigMsg = GameWallet.Signature({ v: v, r: r, s: s });

        submitter.withdrawTokenAdmin(withdraw, sigMsg);

        assertEq(money.balanceOf(player3_addr), wad(235)); // balance 250 - fee 15
        assertEq(gs.balances(player3_addr), wad(0)); // balance 0
        assertEq(gs.nonces(player3_addr), 1); // nonce incremented
    }

    // // should fail if user has insufficient balance
    // function testExample() public { }

    // // should fail if transaction is not submitted by admin
    // function testExample() public { }

    // // should fail if user address does not match signature
    // function testExample() public { }

    // // should fail if expiry is complete
    // function testExample() public { }

    // // should fail if nonce is not next
    // function testExample() public { }

    // // should reset withdrawAfter and balance
    // function testExample() public { }

    // // should send processing fee amount to admin
    // function testExample() public { }

    // // should debit user balance and credit user wallet balance minus processing fee
    // function testExample() public { }

    // // should fail if nonce in signature is lower than current
    // function testExample() public { }

    // // should fail if expiry is in the past
    // function testExample() public { }

    // // should succeed if nonce is next
    // function testExample() public { }
}
