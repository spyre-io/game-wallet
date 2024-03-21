// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { PRBTest } from "@prb/test/PRBTest.sol";
import { console2 } from "forge-std/console2.sol";
import { StdCheats } from "forge-std/StdCheats.sol";
import { GameStaking } from "../src/GameStaking.sol";
import { Admin, Submitter, Player, InitSetup } from "./inittest.sol";

// when staked match is processed
contract ProcessStakedMatchTest is PRBTest, InitSetup {
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

    // // should fail if either signatures have expired
    // function testExample() public { }

    // // should fail if either signatures have bad nonces
    // function testExample() public { }

    // // should fail if stake amounts of both players do not match
    // function testExample() public { }

    // // should fail if fee is higher than both stakes
    // function testExample() public { }

    // // should award winner the total minus fee as internal balance
    // function testExample() public { }

    // // should not change withdrawAfter state
    // function testExample() public { }

    // // should transfer fee balance to admin
    // function testExample() public { }

    // // should fail if winner address is not one of either player
    // function testExample() public { }

    // // should fail if nonce in signature is lower than current
    // function testExample() public { }

    // // should fail if expiry is in the past
    // function testExample() public { }

    // // should succeed if nonce is next
    // function testExample() public { }
}

// when expired message is processed
contract ProcessExpiredMessageTest is PRBTest, InitSetup {
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

    // // should
    // function testExample() public { }

    // // should fail if nonce in signature is lower than current
    // function testExample() public { }

    // // should fail if expiry is in the past
    // function testExample() public { }

    // // should succeed if nonce is next
    // function testExample() public { }
}
