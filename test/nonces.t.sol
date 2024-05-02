// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { GameWallet } from "../src/GameWallet.sol";
import { Admin, Submitter, Player, InitSetup, SigUtils } from "./inittest.sol";

// when a user signs messages with nonces
contract NoncesTest is InitSetup {
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

        money.mint(player3_addr, wad(10_000)); // money deposited into player3 wallet
        money.mint(player4_addr, wad(10_000)); // money deposited into player4 wallet
    }

    // ERC20 USER NONCES
    // should allow user to sign a permit message
    // and submitter to submit the permit message to the erc20 token
    function testAllowPlayerSignPermit() public {
        // get player nonce
        uint256 currentNonce = money.nonces(player3_addr);

        // user signs permit
        bytes32 digest = sigUtils.getPermitTypedDataHash(player3_addr, gs_addr, wad(1000), currentNonce, T0 + 1 days);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, digest);

        // submitter executes permit
        submitter.executePermit(player3_addr, gs_addr, wad(1000), T0 + 1 days, v, r, s);

        assertEq(money.balanceOf(player3_addr), wad(10_000)); // balance stays same
        assertEq(money.allowance(player3_addr, gs_addr), wad(1000)); // gs approved
        assertEq(money.nonces(player3_addr), currentNonce + 1); // nonce incremented
    }

    // GAME WALLET POOLED NONCES
    // should allow user to deposit with a deposit message
    // should allow submitter to process the deposit
    function testDepositWithDepositMessage() public {
        // allowance : 1000
        uint256 currentNonce = money.nonces(player3_addr);
        bytes32 digest = sigUtils.getPermitTypedDataHash(player3_addr, gs_addr, wad(1000), currentNonce, T0 + 1 days);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, digest);
        submitter.executePermit(player3_addr, gs_addr, wad(1000), T0 + 1 days, v, r, s);

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setLatestPooledNonceUsed(_nonce + 1);
        GameWallet.Deposit memory deposit = GameWallet.Deposit({
            user: player3_addr,
            nonce: _nonce,
            expiry: T0 + 1 days,
            amount: wad(500),
            fee: wad(15)
        });
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(player3PrivateKey, sigUtils.getDepositTypedDataHash(deposit));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v2, r: r2, s: s2 });

        submitter.depositTokenAdmin(deposit, signedMsg);

        assertEq(money.balanceOf(player3_addr), wad(9500)); // 10000 - 500
        assertEq(gs.balances(player3_addr), wad(485)); // +500 - 15
        assertEq(gs.balances(submitter_addr), wad(15)); // +15
        assertEq(gs.noncePool(_nonce), T0 + 1 days + 1); // nonce expiry updated
    }

    // should allow user to submit a withdraw message
    // should allow submitter to process the withdraw message
    function testWithdrawWithWithdrawMessage() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setLatestPooledNonceUsed(_nonce + 1);
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 1 days, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });

        submitter.withdrawTokenAdmin(withdraw, signedMsg);

        assertEq(money.balanceOf(player3_addr), wad(10_247)); // 10000 + 500 - 3
        assertEq(gs.balances(player3_addr), wad(0)); // 250 - 250
        assertEq(gs.balances(submitter_addr), wad(3)); // +3
        assertEq(gs.noncePool(_nonce), T0 + 1 days + 1); // nonce expiry updated
    }

    // should allow user to use a new pooled nonce
    // should allow users to sign stake messages
    // should allow submitter to process the stake messages
    function testStakeWithStakeMessage() public {
        addWalletBalance(player3_addr, wad(500));
        addWalletBalance(player4_addr, wad(500));

        uint256 _nonce1 = gs.latestPooledNonceUsed();
        gs.setLatestPooledNonceUsed(_nonce1 + 1);
        GameWallet.Stake memory stake1 =
            GameWallet.Stake({ user: player3_addr, nonce: _nonce1, expiry: T0 + 1 days, amount: wad(10), fee: wad(5) });
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(player3PrivateKey, sigUtils.getStakeTypedDataHash(stake1));
        GameWallet.Signature memory signedMsg1 = GameWallet.Signature({ v: v1, r: r1, s: s1 });

        uint256 _nonce2 = _nonce1 + 1;
        gs.setLatestPooledNonceUsed(_nonce2 + 1);
        GameWallet.Stake memory stake2 =
            GameWallet.Stake({ user: player4_addr, nonce: _nonce2, expiry: T0 + 1 days, amount: wad(10), fee: wad(5) });
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(player4PrivateKey, sigUtils.getStakeTypedDataHash(stake2));
        GameWallet.Signature memory signedMsg2 = GameWallet.Signature({ v: v2, r: r2, s: s2 });

        submitter.processStakedMatch(stake1, stake2, signedMsg1, signedMsg2, uint256(123), player3_addr);

        assertEq(gs.balances(player3_addr), wad(505)); // 500 - 10 + 15
        assertEq(gs.balances(player4_addr), wad(490)); // 500 - 10
        assertEq(gs.balances(submitter_addr), wad(5)); // +5
        assertEq(gs.noncePool(_nonce1), T0 + 1 days + 1); // nonce expiry updated
        assertEq(gs.noncePool(_nonce2), T0 + 1 days + 1); // nonce expiry updated
    }

    // should allow user to use an existing expired pooled nonce
    function testExpiredPooledNonceReuse() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setNonceExpiry(_nonce, T0 + 1 days);

        // forward block.timestamp past nonce expiry
        vm.warp(T0 + 2 days);

        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 3 days, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });

        submitter.withdrawTokenAdmin(withdraw, signedMsg);
        assertEq(gs.noncePool(_nonce), T0 + 3 days + 1); // nonce expiry updated
        assertEq(gs.balances(submitter_addr), wad(3)); // +3
    }

    // should fail if a pooled nonce has not expired before expiry
    function testFailExpiredPooledNonce() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setNonceExpiry(_nonce, T0 + 1 days);

        // forward block.timestamp but leave it before nonce expiry
        vm.warp(T0 + 6 hours);

        // signed message expiry is valid
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 3 days, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });

        submitter.withdrawTokenAdmin(withdraw, signedMsg);
    }

    // should fail if a pooled nonce is past its expiry with an expired signed message
    function testFailNonceExpiredSignedMessageExpired() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setNonceExpiry(_nonce, T0 + 1 days);

        // forward block.timestamp past nonce expiry
        vm.warp(T0 + 2 days);

        // signed message expiry is invalid
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 6 hours, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });

        submitter.withdrawTokenAdmin(withdraw, signedMsg);
    }

    // should allow submitter to reset an expired pooled nonce
    function testSubmitterPooledNonceResetAfterExpiry() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setLatestPooledNonceUsed(_nonce + 1);
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 1 days, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });
        submitter.withdrawTokenAdmin(withdraw, signedMsg);

        assertEq(gs.noncePool(_nonce), T0 + 1 days + 1);

        // forward block.timestamp past nonce expiry
        vm.warp(T0 + 2 days);

        submitter.resetNonceExpiry(_nonce);
        assertEq(gs.noncePool(_nonce), 0);
    }

    // should fail if submitter resets a pooled nonce not expired
    function testFailSubmitterPooledNonceResetBeforeExpiry() public {
        addWalletBalance(player3_addr, wad(250));

        uint256 _nonce = gs.latestPooledNonceUsed();
        gs.setLatestPooledNonceUsed(_nonce + 1);
        GameWallet.Withdraw memory withdraw =
            GameWallet.Withdraw({ user: player3_addr, nonce: _nonce, expiry: T0 + 1 days, fee: wad(3) });
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(player3PrivateKey, sigUtils.getWithdrawTypedDataHash(withdraw));
        GameWallet.Signature memory signedMsg = GameWallet.Signature({ v: v, r: r, s: s });
        submitter.withdrawTokenAdmin(withdraw, signedMsg);

        assertEq(gs.noncePool(_nonce), T0 + 1 days + 1);

        // forward block.timestamp before nonce expiry
        vm.warp(T0 + 6 hours);

        submitter.resetNonceExpiry(_nonce);
    }
}
