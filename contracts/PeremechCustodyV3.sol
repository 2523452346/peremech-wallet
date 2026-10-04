// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WebAuthn} from "./WebAuthn.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// A user's personal deposit address. Deployed deterministically (CREATE2) by the
/// custody contract, so no private key for it exists anywhere.
/// It can do exactly one thing: hand its tokens to the custody contract.
contract DepositVault {
    address public immutable custody;

    constructor() {
        custody = msg.sender;
    }

    function sweep(IERC20 token) external returns (uint256 amount) {
        require(msg.sender == custody, "only custody");
        amount = token.balanceOf(address(this));
        if (amount > 0) {
            require(token.transfer(custody, amount), "sweep failed");
        }
    }
}

/// Custody where users, not the platform, control the money.
///
/// Every movement of a user's balance — a donation, a withdrawal, adding a device —
/// is authorised by a signature from that user's passkey, which lives in the secure
/// element of their phone or laptop. The platform assembles the transaction and pays
/// the network fee, but it cannot forge that signature, and it cannot block a
/// withdrawal either: donate() and withdraw() accept a call from any sender.
///
/// The platform holds two keys and neither of them can move user funds:
///   server — records a user's FIRST passkey, having checked they are signed in
///            under that account. The contract cannot verify a website login itself,
///            so someone has to vouch for it once; after that the record is permanent
///            and not even the platform can replace it.
///   owner  — can only rotate the server key, in case that key is compromised.
///
/// There is deliberately no function to withdraw on a user's behalf, to adjust a
/// balance, to pause the contract or to change the fee. The contract is not
/// upgradeable, so this cannot be added later.
contract PeremechCustodyV3 {
    uint256 public constant PLATFORM_FEE_BPS = 500;
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MIN_DONATION = 1_000_000; // $1 (6 decimals)
    uint256 public constant MAX_PASSKEYS = 5; // spare devices

    // Action labels go inside the signed message, so a signature meant for a
    // withdrawal cannot be replayed as a donation.
    bytes32 public constant ACTION_DONATE = keccak256("peremech.donate");
    bytes32 public constant ACTION_WITHDRAW = keccak256("peremech.withdraw");
    bytes32 public constant ACTION_ADD_PASSKEY = keccak256("peremech.addPasskey");
    bytes32 public constant ACTION_SET_RECOVERY = keccak256("peremech.setRecovery");

    IERC20 public immutable token;
    address public immutable platformWallet;

    address public owner;
    address public server;

    mapping(bytes32 => uint256) public balanceOf;
    /// Public halves of a user's passkeys: P-256 coordinates (x, y).
    mapping(bytes32 => uint256[2][]) private _passkeys;
    /// Command counter, so the same signature cannot be used twice.
    mapping(bytes32 => uint256) public nonceOf;
    /// Fallback owner: an ordinary wallet address that can withdraw this user's
    /// funds without a passkey. A passkey only works on a page served from the
    /// website's domain; this key works from any wallet, anywhere, forever — so the
    /// money stays reachable even if the domain itself is lost or taken away.
    mapping(bytes32 => address) public recoveryOf;

    event Deposited(bytes32 indexed user, address indexed vault, uint256 amount);
    event Donated(
        bytes32 indexed from,
        bytes32 indexed to,
        address recipientAddress,
        uint256 amount,
        uint256 platformFee,
        string memo
    );
    event Withdrawn(bytes32 indexed user, address indexed to, uint256 amount);
    event PasskeyAdded(bytes32 indexed user, uint256 indexed keyIndex, uint256 x, uint256 y);
    event RecoverySet(bytes32 indexed user, address indexed previous, address indexed recovery);
    event ServerChanged(address indexed previousServer, address indexed newServer);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(IERC20 token_, address owner_, address server_, address platformWallet_) {
        require(address(token_) != address(0), "bad token");
        require(owner_ != address(0), "bad owner");
        require(server_ != address(0), "bad server");
        require(platformWallet_ != address(0), "bad platform");
        token = token_;
        owner = owner_;
        server = server_;
        platformWallet = platformWallet_;
    }

    // ---------------------------------------------------------------- addresses and balances

    /// A user's personal deposit address. A pure formula — no transaction, no gas.
    function depositAddress(bytes32 user) public view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), user, keccak256(type(DepositVault).creationCode))
        );
        return address(uint160(uint256(h)));
    }

    /// Hash of the deposit vault's creation code, so a server can derive addresses
    /// locally. Exposed here instead of being copied into server code: the hash
    /// depends on the compiler build, and the two must never drift apart.
    function depositVaultInitCodeHash() external pure returns (bytes32) {
        return keccak256(type(DepositVault).creationCode);
    }

    /// Everything available to a user: credited inside plus a deposit not yet swept.
    function available(bytes32 user) public view returns (uint256) {
        return balanceOf[user] + token.balanceOf(depositAddress(user));
    }

    /// Pull a deposit from a user's address into custody. Open to anyone:
    /// the money is credited to the address owner regardless of who calls.
    function sweep(bytes32 user) external returns (uint256) {
        return _sweep(user);
    }

    function _sweep(bytes32 user) internal returns (uint256 amount) {
        address vault = depositAddress(user);
        if (vault.code.length == 0) {
            if (token.balanceOf(vault) == 0) {
                return 0; // nothing to collect — do not waste gas on deployment
            }
            DepositVault deployed = new DepositVault{salt: user}();
            require(address(deployed) == vault, "vault address mismatch");
        }
        amount = DepositVault(vault).sweep(token);
        if (amount > 0) {
            balanceOf[user] += amount;
            emit Deposited(user, vault, amount);
        }
    }

    // ---------------------------------------------------------------- passkeys

    function passkeyCount(bytes32 user) public view returns (uint256) {
        return _passkeys[user].length;
    }

    function passkeyAt(bytes32 user, uint256 index) external view returns (uint256 x, uint256 y) {
        uint256[2] storage key = _passkeys[user][index];
        return (key[0], key[1]);
    }

    /// The first passkey together with the fallback wallet, recorded by the server key —
    /// the only party able to check that the person is signed in under this very user id.
    /// Knowing someone else's user id is not enough; their login session is required too.
    ///
    /// Both keys are handed over in one call so the user confirms once instead of twice.
    /// This grants the server no extra power: whoever records the first passkey already
    /// owns the account outright. From here on neither entry can be taken away — the
    /// passkey can never be replaced by anyone, and the fallback wallet only by the user.
    function registerFirstPasskey(bytes32 user, uint256 x, uint256 y, address recovery) external {
        require(msg.sender == server, "only server");
        require(user != bytes32(0), "bad user");
        require(_passkeys[user].length == 0, "passkey already set");
        require(x != 0 || y != 0, "bad passkey");
        require(recovery != address(0), "bad recovery");

        _passkeys[user].push([x, y]);
        emit PasskeyAdded(user, 0, x, y);

        emit RecoverySet(user, address(0), recovery);
        recoveryOf[user] = recovery;
    }

    /// A spare device. Only the user can authorise this, by signing with a passkey
    /// already on record. The platform has no way in.
    function addPasskey(bytes32 user, uint256 keyIndex, uint256 x, uint256 y, WebAuthn.Auth calldata auth)
        external
    {
        require(_passkeys[user].length < MAX_PASSKEYS, "too many passkeys");
        require(x != 0 || y != 0, "bad passkey");

        _requireSignature(user, keyIndex, addPasskeyChallenge(user, x, y, _useNonce(user)), auth);

        _passkeys[user].push([x, y]);
        emit PasskeyAdded(user, _passkeys[user].length - 1, x, y);
    }

    // ---------------------------------------------------------------- the signed command
    //
    // What the user actually signs. The chain id and this contract's address are part
    // of it, so a signature cannot be replayed on another chain or another contract.
    // Exposed publicly so a server can check its own computation against the contract
    // rather than keeping a second copy of the formula.

    /// memoHash — keccak256 of the donation text. Taking the hash rather than the
    /// string keeps donate() within stack limits and is simpler for a server too.
    function donateChallenge(bytes32 from, bytes32 to, uint256 amount, bytes32 memoHash, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(block.chainid, address(this), ACTION_DONATE, from, to, amount, memoHash, nonce)
        );
    }

    function withdrawChallenge(bytes32 user, address to, uint256 amount, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), ACTION_WITHDRAW, user, to, amount, nonce));
    }

    function addPasskeyChallenge(bytes32 user, uint256 x, uint256 y, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), ACTION_ADD_PASSKEY, user, x, y, nonce));
    }

    function setRecoveryChallenge(bytes32 user, address recovery, uint256 nonce)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), ACTION_SET_RECOVERY, user, recovery, nonce));
    }

    // ---------------------------------------------------------------- fallback owner

    /// Nominate (or replace) the wallet that can withdraw without a passkey.
    /// Only the user can do this, by signing with a passkey already on record.
    function setRecovery(bytes32 user, address recovery, uint256 keyIndex, WebAuthn.Auth calldata auth)
        external
    {
        require(recovery != address(0), "bad recovery");

        _requireSignature(user, keyIndex, setRecoveryChallenge(user, recovery, _useNonce(user)), auth);

        emit RecoverySet(user, recoveryOf[user], recovery);
        recoveryOf[user] = recovery;
    }

    /// Withdrawal by the fallback owner. No passkey, no website, no domain — the
    /// wallet simply calls this itself, so the funds cannot be locked away by the
    /// platform disappearing or by the domain being lost.
    function withdrawByRecovery(bytes32 user, address to, uint256 amount) external {
        require(msg.sender == recoveryOf[user], "not recovery");
        require(to != address(0), "bad recipient");
        require(amount > 0, "bad amount");

        if (balanceOf[user] < amount) {
            _sweep(user);
        }
        require(balanceOf[user] >= amount, "insufficient funds");

        balanceOf[user] -= amount;
        require(token.transfer(to, amount), "transfer failed");

        emit Withdrawn(user, to, amount);
    }

    // ---------------------------------------------------------------- user money

    /// A donation, authorised by the sender's own passkey. The platform merely
    /// delivers the signed command to the network and pays the fee.
    /// 95% is a real token transfer to the recipient's address, 5% to the platform.
    function donate(
        bytes32 from,
        bytes32 to,
        uint256 amount,
        string calldata memo,
        uint256 keyIndex,
        WebAuthn.Auth calldata auth
    ) external {
        require(from != bytes32(0) && to != bytes32(0), "bad user");
        require(from != to, "self donation");
        require(amount >= MIN_DONATION, "min 1 usd");
        // A recipient without a passkey cannot be paid: their money would otherwise
        // sit under the platform's control, which must never happen here.
        require(_passkeys[to].length > 0, "recipient has no passkey");

        _checkDonateSignature(from, to, amount, memo, keyIndex, auth);

        if (balanceOf[from] < amount) {
            _sweep(from);
        }
        require(balanceOf[from] >= amount, "insufficient funds");

        uint256 fee = (amount * PLATFORM_FEE_BPS) / BPS_DENOMINATOR;
        uint256 payout = amount - fee;

        balanceOf[from] -= amount;

        address recipient = depositAddress(to);
        require(token.transfer(recipient, payout), "payout failed");
        require(token.transfer(platformWallet, fee), "fee failed");

        emit Donated(from, to, recipient, amount, fee, memo);
    }

    /// Split out of donate() out of necessity rather than style: otherwise the
    /// compiler runs out of stack slots for all the parameters at once.
    function _checkDonateSignature(
        bytes32 from,
        bytes32 to,
        uint256 amount,
        string calldata memo,
        uint256 keyIndex,
        WebAuthn.Auth calldata auth
    ) internal {
        bytes32 challenge = donateChallenge(from, to, amount, keccak256(bytes(memo)), _useNonce(from));
        _requireSignature(from, keyIndex, challenge, auth);
    }

    /// Withdrawal to an outside address, authorised by the owner of the money.
    /// Open to any sender: the platform can neither forge the command nor stop it
    /// from being delivered, so funds remain reachable even without the website.
    function withdraw(bytes32 user, address to, uint256 amount, uint256 keyIndex, WebAuthn.Auth calldata auth)
        external
    {
        require(to != address(0), "bad recipient");
        require(amount > 0, "bad amount");

        _requireSignature(user, keyIndex, withdrawChallenge(user, to, amount, _useNonce(user)), auth);

        if (balanceOf[user] < amount) {
            _sweep(user);
        }
        require(balanceOf[user] >= amount, "insufficient funds");

        balanceOf[user] -= amount;
        require(token.transfer(to, amount), "transfer failed");

        emit Withdrawn(user, to, amount);
    }

    function _useNonce(bytes32 user) internal returns (uint256 nonce) {
        nonce = nonceOf[user];
        nonceOf[user] = nonce + 1;
    }

    function _requireSignature(bytes32 user, uint256 keyIndex, bytes32 challenge, WebAuthn.Auth calldata auth)
        internal
        view
    {
        uint256[2][] storage keys = _passkeys[user];
        require(keyIndex < keys.length, "no such passkey");
        require(WebAuthn.verify(challenge, auth, keys[keyIndex][0], keys[keyIndex][1]), "bad signature");
    }

    // ---------------------------------------------------------------- platform keys
    //
    // Everything the platform can do lives below this line. Note that none of it
    // touches a user's balance.

    /// The server key was compromised — install a new one; the old one becomes useless.
    function setServer(address server_) external onlyOwner {
        require(server_ != address(0), "bad server");
        emit ServerChanged(server, server_);
        server = server_;
    }

    function transferOwnership(address owner_) external onlyOwner {
        require(owner_ != address(0), "bad owner");
        emit OwnerChanged(owner, owner_);
        owner = owner_;
    }
}
