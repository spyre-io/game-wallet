// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { IERC20 } from "@openzeppelin/token/ERC20/IERC20.sol";
import { AccessControl } from "@openzeppelin/access/AccessControl.sol";

interface USDC {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        external;
}

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

        if (withdrawal_delay > 7 days) {
            revert WithdrawalDelayExceedsLimit(withdrawal_delay);
        }

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

    // --- Errors ---
    error WithdrawalDelayExceedsLimit(uint256 duration);
    error TokenTransferFailed(address from, address to, uint256 amount);
    error DepositExceedsLimit(uint256 balance, uint256 limit);
    error UserWithdrawalDelayIncomplete(uint256 currentTimestamp, uint256 withdrawAfterTimestamp);
    error SignerUserAddressMismatch(address inputUser, address recoveredSigner);
    error SignatureExpired(uint256 expiryTimestamp, uint256 currentTimestamp);
    error NonceHasNotExpired(uint256 currentTimestamp, uint256 nonceExpiryTimestamp);
    error StakeMismatch(uint256 stake1, uint256 stake2);
    error FeeMismatch(uint256 fee1, uint256 fee2);
    error WinnerNotAmongStakers(address winner, address staker1, address staker2);

    // --- Events ---
    event BalanceUpdate(address indexed user, uint256 currentBalance);
    event GameUpdate(uint256 indexed matchId, address winner, address otherPlayer, uint256 payout, uint256 fee);

    // --- Balance Management ---
    // deposit an amount
    function depositToken(uint256 amount) external {
        // transfer token balance from msg.sender to game wallet
        bool transferStatus = token.transferFrom(msg.sender, address(this), amount);
        if (transferStatus == false) {
            revert TokenTransferFailed(msg.sender, address(this), amount);
        }

        // update new balance
        balances[msg.sender] = balances[msg.sender] + amount;
        // revert if total user balance exceeds max_balance amount
        if (balances[msg.sender] > max_balance) {
            revert DepositExceedsLimit(balances[msg.sender], max_balance);
        }

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
        if (block.timestamp < withdrawAfter[msg.sender]) {
            revert UserWithdrawalDelayIncomplete(block.timestamp, withdrawAfter[msg.sender]);
        }

        uint256 balance = balances[msg.sender];

        // reset withdrawAfter and balance
        balances[msg.sender] = 0;
        withdrawAfter[msg.sender] = 0;

        // transfer a users entire balance to them
        bool transferStatus = token.transfer(msg.sender, balance);
        if (transferStatus == false) {
            revert TokenTransferFailed(address(this), msg.sender, balance);
        }

        emit BalanceUpdate(msg.sender, 0);
    }

    // server can deposit an amount with a signed message
    function depositTokenAdmin(
        Deposit memory deposit,
        Signature memory signedMsg
    )
        external
        onlyRole(TXN_SUBMITTER_ROLE)
    {
        // use these values for Permit
        // PERMIT_TYPE = Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
        // PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

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

        if (deposit.user != ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s)) {
            revert SignerUserAddressMismatch(deposit.user, ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s));
        }
        if (deposit.expiry < block.timestamp) {
            revert SignatureExpired(deposit.expiry, block.timestamp);
        }

        _resetNonceExpiry(deposit.nonce);
        noncePool[deposit.nonce] = (deposit.expiry + 1);

        // transfer token balance from user to game wallet
        bool transferStatus = token.transferFrom(deposit.user, address(this), deposit.amount);
        if (transferStatus == false) {
            revert TokenTransferFailed(deposit.user, address(this), deposit.amount);
        }

        // withdrawal timestamp is reset
        // any pending withdrawals are cancelled and have to be initiated again
        withdrawAfter[deposit.user] = type(uint256).max;

        // txn submitter collects fee
        balances[msg.sender] = balances[msg.sender] + deposit.fee;
        // calculate new balance and ensure it does not exceed max_balance of game wallet
        balances[deposit.user] = balances[deposit.user] + deposit.amount - deposit.fee;
        // revert if total user balance exceeds max_balance amount
        if (balances[deposit.user] > max_balance) {
            revert DepositExceedsLimit(balances[deposit.user], max_balance);
        }

        emit BalanceUpdate(deposit.user, balances[deposit.user]);
    }

    // server can execute deposit with transfer authorization (eip3009)
    function receiveTokenAdmin(
        address user,
        uint256 amount,
        uint256 expiry,
        bytes32 nonce,
        uint256 fee,
        Signature memory signedMsg
    )
        external
        onlyRole(TXN_SUBMITTER_ROLE)
    {
        // RECEIVE_WITH_AUTHORIZATION_TYPE : ReceiveWithAuthorization(address from,address to,uint256 value,uint256
        // validAfter,uint256 validBefore,bytes32 nonce)
        // RECEIVE_WITH_AUTHORIZATION_TYPEHASH : 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

        // nonce value here is an eip3009 authorization nonce, any bytes32 value that has not been previously used
        // token.authorizationState(address user, bytes32 nonce) should return false for a valid nonce

        // execute authorization to receive token balance
        // reverts upon failed transfer, does not return false
        // to address is always this game wallet address
        // validAfter is always set to 0
        // signature format change
        USDC(address(token)).receiveWithAuthorization(
            user, address(this), amount, 0, expiry, nonce, signedMsg.v, signedMsg.r, signedMsg.s
        );
        // receive is used to restrict the ability to transfer to the game wallet contract
        // to avoid griefing where a balance is transferred from user without being recorded by the game wallet

        // withdrawal timestamp is reset
        withdrawAfter[user] = type(uint256).max;

        // fee is not signed off by the user in the signed message
        // fee to txn submitter
        balances[msg.sender] = balances[msg.sender] + fee;

        // token balance - fee to user
        balances[user] = balances[user] + amount - fee;
        // revert if total user balance exceeds max_balance amount
        if (balances[user] > max_balance) {
            revert DepositExceedsLimit(balances[user], max_balance);
        }

        emit BalanceUpdate(user, balances[user]);
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

        if (withdraw.user != ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s)) {
            revert SignerUserAddressMismatch(withdraw.user, ecrecover(digest, signedMsg.v, signedMsg.r, signedMsg.s));
        }
        if (withdraw.expiry < block.timestamp) {
            revert SignatureExpired(withdraw.expiry, block.timestamp);
        }
        _resetNonceExpiry(withdraw.nonce);
        noncePool[withdraw.nonce] = (withdraw.expiry + 1);

        uint256 balance = balances[withdraw.user];
        // reset user balance
        balances[withdraw.user] = 0;

        // reset withdrawAfter
        withdrawAfter[withdraw.user] = 0;

        // send fee amount to admin address (msg.sender)
        balances[msg.sender] = balances[msg.sender] + withdraw.fee;

        // transfer a users balance minus fee to them
        bool transferStatus = token.transfer(withdraw.user, (balance - withdraw.fee));
        if (transferStatus == false) {
            revert TokenTransferFailed(address(this), withdraw.user, (balance - withdraw.fee));
        }

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

        if (stake1.user != ecrecover(digest1, signedMsg1.v, signedMsg1.r, signedMsg1.s)) {
            revert SignerUserAddressMismatch(stake1.user, ecrecover(digest1, signedMsg1.v, signedMsg1.r, signedMsg1.s));
        }
        if (stake2.user != ecrecover(digest2, signedMsg2.v, signedMsg2.r, signedMsg2.s)) {
            revert SignerUserAddressMismatch(stake2.user, ecrecover(digest2, signedMsg2.v, signedMsg2.r, signedMsg2.s));
        }

        if (stake1.expiry < block.timestamp) {
            revert SignatureExpired(stake1.expiry, block.timestamp);
        }
        if (stake2.expiry < block.timestamp) {
            revert SignatureExpired(stake2.expiry, block.timestamp);
        }

        _resetNonceExpiry(stake1.nonce);
        noncePool[stake1.nonce] = (stake1.expiry + 1);
        _resetNonceExpiry(stake2.nonce);
        noncePool[stake2.nonce] = (stake2.expiry + 1);

        if (stake1.amount != stake2.amount) {
            revert StakeMismatch(stake1.amount, stake2.amount);
        }
        if (stake1.fee != stake2.fee) {
            revert FeeMismatch(stake1.fee, stake2.fee);
        }
        if (winner != stake1.user && winner != stake2.user) {
            revert WinnerNotAmongStakers(winner, stake1.user, stake2.user);
        }

        // debit from player 1 and player 2
        balances[stake1.user] = balances[stake1.user] - stake1.amount;
        balances[stake2.user] = balances[stake2.user] - stake2.amount;

        // send fee to transaction submitter address
        balances[msg.sender] = balances[msg.sender] + stake1.fee;

        // credit winner
        uint256 payout = (stake1.amount + stake2.amount - stake1.fee);
        balances[winner] = balances[winner] + payout;

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
        if (block.timestamp < noncePool[nonce]) {
            revert NonceHasNotExpired(block.timestamp, noncePool[nonce]);
        }

        // nonce can be safely reset as the signed message relying on it to
        // not be replayed again has expired
        noncePool[nonce] = 0;
    }

    function resetNonceExpiry(uint256 nonce) external onlyRole(TXN_SUBMITTER_ROLE) {
        _resetNonceExpiry(nonce);
    }
}
