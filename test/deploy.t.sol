// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { GameWallet } from "../src/GameWallet.sol";
import { Admin, Submitter, Player, InitSetup } from "./inittest.sol";

// when an admin deploys the game staking contract
contract DeploymentTest is InitSetup {
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
    }

    // should mint money to player address
    function testMoneyMint() public {
        money.mint(player1_addr, wad(1234));
        assertEq(money.balanceOf(player1_addr), wad(1234));
    }

    // should set max balance
    function testMaxBalanceSet() public {
        assertEq(gs.max_balance(), wad(1000));
    }

    // should set withdrawal delay
    function testWithdrawalDelaySet() public {
        assertEq(gs.withdrawal_delay(), 3 hours);
    }

    // should fail if withdrawal delay input is greater than 7 days
    function testFailWithdrawalDelayLimit() public {
        // try to deploy a new admin with withdrawal delay set to 8 days
        new Admin(address(money), wad(1000), 8 days);
    }

    // should set correct role for admin
    function testAdminRoleSet() public {
        assertTrue(gs.hasRole(gs.DEFAULT_ADMIN_ROLE(), admin_addr));
    }

    // should work with tokens having 18 decimals
    function testToken18Decimals() public {
        // token should be set
        assertEq(money.name(), "MONEY");
        assertEq(money.symbol(), "MONEY");
        assertEq(money.decimals(), 18);

        money.mint(player1_addr, wad(10_000)); // money deposited into player1 wallet
        assertEq(money.balanceOf(player1_addr), wad(10_000));

        money.mint(player2_addr, wad(10_000)); // money deposited into player2 wallet
        assertEq(money.balanceOf(player2_addr), wad(10_000));
    }

    // should work with tokens having greater than 18 decimals
    // function testTokenMoreThan18Decimals() public { }

    // should work with tokens having less than 18 decimals
    // function testTokenLessThan18Decimals() public { }
}

// when eip712 methods are setup
contract DeployEIP712Test is InitSetup {
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
    }

    // // should set domain separator correctly for given chain
    // function testExample() public { }

    // // should calculate correct type hashes for withdraw signed message type and stake signed message type
    // function testExample() public { }
}
