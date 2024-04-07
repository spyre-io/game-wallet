// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { AccessControl } from "@openzeppelin/access/AccessControl.sol";

contract GameWallet is AccessControl {
    // --- Staking Setup ---
    IERC20 public token; // ex: USDC token address
    uint256 public max_balance; // ex: USDC has 6 decimals, set to 1000e6 for 1000 USDC
    uint256 public withdrawal_delay; // ex: 24 hours

    // --- User Balances ---
    // user address => balance
    mapping(address => uint256) public balances;
    // user address => their withdrawAfter timestamp
    mapping(address => uint256) public withdrawAfter;

    struct Deposit {
        address user;
        uint256 nonce;
        uint256 expiry;
        uint256 amount;
        uint256 fee;
    }

    struct Withdraw {
        address user;
        uint256 nonce;
        uint256 expiry;
        uint256 fee;
    }

    struct Stake {
        address user;
        uint256 nonce;
        uint256 expiry;
        uint256 amount;
        uint256 fee;
    }

    struct Signature {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // --- EIP712 ---
    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant DEPOSIT_TYPEHASH =
        keccak256("Deposit(address user,uint256 nonce,uint256 expiry,uint256 amount,uint256 fee)");
    bytes32 public constant WITHDRAW_TYPEHASH =
        keccak256("Withdraw(address user,uint256 nonce,uint256 expiry,uint256 fee)");
    bytes32 public constant STAKE_TYPEHASH =
        keccak256("Stake(address user,uint256 nonce,uint256 expiry,uint256 amount,uint256 fee)");

    mapping(uint256 => uint256) public noncePool; // nonce value => nonce expiry

    // Auth
    bytes32 public constant TXN_SUBMITTER_ROLE = keccak256("TXN_SUBMITTER_ROLE");

    constructor(address _token, uint256 _max_balance, uint256 _withdrawal_delay) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender); // deployer holds the admin role to assign addresses roles

        token = IERC20(_token);
        max_balance = _max_balance;
        withdrawal_delay = _withdrawal_delay;

        require(withdrawal_delay <= 7 days, "constructor/incorrect-delay");

        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("gamestaking")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    event BalanceUpdate(address indexed user, uint256 currentBalance);
    event GameUpdate(uint256 indexed matchId, address winner, address otherPlayer, uint256 payout, uint256 fee);

    // --- Balance Management ---
    // deposit an amount
    function depositToken(uint256 amount) external {
        // transfer token balance from msg.sender to game wallet
        require(token.transferFrom(msg.sender, address(this), amount), "depositToken/token-transfer-from-user-failed");

        // calculate new balance and ensure it does not exceed max_balance of game wallet
        balances[msg.sender] = balances[msg.sender] + amount;
        require(balances[msg.sender] <= max_balance, "depositToken/deposit-amount-exceeds-max-balance");

        // withdrawal timestamp is reset
        // any pending withdrawals are cancelled and have to be initiated again
        withdrawAfter[msg.sender] = type(uint256).max;

        emit BalanceUpdate(msg.sender, balances[msg.sender]);
    }

    // initiate withdrawal on entire balance
    function initiateWithdrawal() external {
        // set valid withdrawal timestamp on msg.sender balance
        withdrawAfter[msg.sender] = block.timestamp + withdrawal_delay;
    }

    // cancel pending withdrawal
    function cancelWithdrawal() external {
        // reset withdrawal timestamp on msg.sender balance
        // pending withdrawal is cancelled
        withdrawAfter[msg.sender] = type(uint256).max;
    }

    function withdrawToken() external {
        // check if withdraw after was set and has passed
        require(withdrawAfter[msg.sender] <= block.timestamp, "withdrawToken/delay-incomplete");

        uint256 balance = balances[msg.sender];

        // reset withdrawAfter and balance
        balances[msg.sender] = 0;
        withdrawAfter[msg.sender] = 0;

        // transfer a users entire balance to them
        require(token.transfer(msg.sender, balance), "withdrawToken/token-transfer-to-user-failed");

        emit BalanceUpdate(msg.sender, 0);
    }

    // server can deposit an amount
    function depositTokenAdmin(
        Deposit memory deposit,
        Signature memory signedMsg
    )
        external
        onlyRole(TXN_SUBMITTER_ROLE)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        DEPOSIT_TYPEHASH, deposit.user, deposit.nonce, deposit.expiry, deposit.amount, deposit.fee
                    )
                )
            )
        );

        require(
            deposit.user == ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s),
            "depositTokenAdmin/signer-user-address-mismatch"
        );

        require(deposit.expiry == 0 || block.timestamp <= deposit.expiry, "depositTokenAdmin/signature-expired");
        _resetNonceExpiry(deposit.nonce);
        noncePool[deposit.nonce] = (deposit.expiry + 1);

        // transfer token balance from user to game wallet
        require(
            token.transferFrom(deposit.user, address(this), deposit.amount),
            "depositTokenAdmin/token-transfer-from-user-failed"
        );

        // calculate new balance and ensure it does not exceed max_balance of game wallet
        balances[deposit.user] = balances[deposit.user] + deposit.amount;
        require(balances[deposit.user] <= max_balance, "depositTokenAdmin/deposit-amount-exceeds-max-balance");

        // withdrawal timestamp is reset
        // any pending withdrawals are cancelled and have to be initiated again
        withdrawAfter[deposit.user] = type(uint256).max;

        emit BalanceUpdate(deposit.user, balances[deposit.user]);
    }

    // server can finalize withdrawal anytime
    function withdrawTokenAdmin(
        Withdraw memory withdraw,
        Signature memory signedMsg
    )
        external
        onlyRole(TXN_SUBMITTER_ROLE)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(WITHDRAW_TYPEHASH, withdraw.user, withdraw.nonce, withdraw.expiry, withdraw.fee))
            )
        );

        require(
            withdraw.user == ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s),
            "withdrawTokenAdmin/signer-user-address-mismatch"
        );
        require(withdraw.expiry == 0 || block.timestamp <= withdraw.expiry, "withdrawTokenAdmin/signature-expired");
        _resetNonceExpiry(withdraw.nonce);
        noncePool[withdraw.nonce] = (withdraw.expiry + 1);

        uint256 balance = balances[withdraw.user];

        // reset withdrawAfter and balance
        balances[withdraw.user] = 0;
        withdrawAfter[withdraw.user] = 0;

        // send fee amount to admin address (msg.sender)
        require(token.transfer(msg.sender, withdraw.fee), "withdrawTokenAdmin/token-transfer-to-user-failed");
        // transfer a users balance minus fee to them
        require(
            token.transfer(withdraw.user, (balance - withdraw.fee)), "withdrawTokenAdmin/token-transfer-to-admin-failed"
        );

        emit BalanceUpdate(withdraw.user, 0);
    }

    // --- Match Management ---
    function processStakedMatch(
        Stake memory stake1,
        Stake memory stake2,
        Signature memory signedMsg1,
        Signature memory signedMsg2,
        uint256 matchId,
        address winner
    )
        external
        onlyRole(TXN_SUBMITTER_ROLE)
    {
        bytes32 digest1 = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(STAKE_TYPEHASH, stake1.user, stake1.nonce, stake1.expiry, stake1.amount, stake1.fee)
                )
            )
        );

        bytes32 digest2 = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(STAKE_TYPEHASH, stake2.user, stake2.nonce, stake2.expiry, stake2.amount, stake2.fee)
                )
            )
        );

        require(
            stake1.user == ecrecover(digest1, signedMsg1.v, signedMsg1.r, signedMsg1.s),
            "processStakedMatch/stake1/signer-user-address-mismatch"
        );
        require(
            stake2.user == ecrecover(digest2, signedMsg2.v, signedMsg2.r, signedMsg2.s),
            "processStakedMatch/stake2/signer-user-address-mismatch"
        );

        require(stake1.expiry == 0 || block.timestamp <= stake1.expiry, "processStakedMatch/stake1/signature-expired");
        require(stake2.expiry == 0 || block.timestamp <= stake2.expiry, "processStakedMatch/stake2/signature-expired");

        _resetNonceExpiry(stake1.nonce);
        noncePool[stake1.nonce] = (stake1.expiry + 1);
        _resetNonceExpiry(stake2.nonce);
        noncePool[stake2.nonce] = (stake2.expiry + 1);

        require(stake1.amount == stake2.amount, "processStakedMatch/stake-amounts-mismatch");
        require(stake1.fee == stake2.fee, "processStakedMatch/fee-amounts-mismatch");
        require(winner == stake1.user || winner == stake2.user, "processStakedMatch/signers-not-winner");

        // debit from player 1 and player 2
        balances[stake1.user] = balances[stake1.user] - stake1.amount;
        balances[stake2.user] = balances[stake2.user] - stake2.amount;

        // credit winner balance
        uint256 payout = (stake1.amount + stake2.amount - stake1.fee);
        balances[winner] = balances[winner] + payout;

        // send fee to transaction submitter address
        require(token.transfer(msg.sender, stake1.fee), "processStakedMatch/token-transfer-to-admin-failed");

        address otherPlayer = (stake1.user == winner) ? stake1.user : stake2.user;
        emit GameUpdate(matchId, winner, otherPlayer, payout, stake1.fee);

        emit BalanceUpdate(winner, balances[winner]);
        emit BalanceUpdate(otherPlayer, balances[otherPlayer]);
    }

    // --- Convenience Read Only functions ---
    function depositSignedCheck(Deposit memory deposit, Signature memory signedMsg) external view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(
                    abi.encode(
                        DEPOSIT_TYPEHASH, deposit.user, deposit.nonce, deposit.expiry, deposit.amount, deposit.fee
                    )
                )
            )
        );

        return ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s);
    }

    function withdrawSignedCheck(
        Withdraw memory withdraw,
        Signature memory signedMsg
    )
        external
        view
        returns (address)
    {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(WITHDRAW_TYPEHASH, withdraw.user, withdraw.nonce, withdraw.expiry, withdraw.fee))
            )
        );

        return ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s);
    }

    function stakeSignedCheck(Stake memory stake, Signature memory signedMsg) external view returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(STAKE_TYPEHASH, stake.user, stake.nonce, stake.expiry, stake.amount, stake.fee))
            )
        );

        return ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s);
    }

    // --- Nonce Management ---
    function _resetNonceExpiry(uint256 nonce) internal {
        // check that current block timestamp is past nonce expiry timestamp
        require(noncePool[nonce] < block.timestamp, "game-wallet/nonce-has-not-expired");

        // nonce can be safely reset as the signed message relying on it to
        // not be replayed again has expired
        noncePool[nonce] = 0;
    }

    function resetNonceExpiry(uint256 nonce) external onlyRole(TXN_SUBMITTER_ROLE) {
        _resetNonceExpiry(nonce);
    }
}
