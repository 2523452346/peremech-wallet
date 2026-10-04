// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PoseidonT3} from "./PoseidonT3.sol";
import {WebAuthn} from "../WebAuthn.sol";

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// The part of the custody (PeremechCustodyV3) the box relies on: a withdrawal the
/// owner of the money signed with their passkey, deliverable by anyone.
interface ICustody {
    function withdraw(bytes32 user, address to, uint256 amount, uint256 keyIndex, WebAuthn.Auth calldata auth) external;
}

interface IAnonBoxVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata pubSignals
    ) external view returns (bool);
}

/// Anonymous donation box.
///
/// A donor drops a sealed envelope: a fixed sum of money plus a commitment
/// Poseidon(owner, blinding) that only the intended recipient can later prove is
/// theirs, and an encrypted letter only the recipient can read. Everyone sees that
/// someone put money into the box; nobody can see for whom.
///
/// The recipient takes money out with a zero-knowledge proof: "these envelopes are in
/// the box, they are mine, and I have not taken them before" — without revealing which
/// envelopes they are. The recipient address, the relayer and its fee are part of the
/// proof, so whoever delivers the withdrawal cannot redirect it.
///
/// One box — one denomination. The sum is never inside an envelope, otherwise a donor
/// could claim a larger sum than they paid in.
///
/// There is no owner and no admin: nothing can be paused, changed, frozen or taken out
/// other than by a valid proof. The platform wallet only receives its fee on deposit.
contract AnonBox {
    uint256 public constant FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint32 public constant LEVELS = 20;
    uint32 public constant ROOT_HISTORY = 100;
    uint256 public constant MAX_INPUTS = 4;
    /// Letter length limit: enough for a name and a message, not for spam.
    uint256 public constant MAX_ENVELOPE = 1024;
    uint256 public constant PLATFORM_FEE_BPS = 500; // 5%

    IERC20 public immutable token;
    IAnonBoxVerifier public immutable verifier;
    address public immutable platformWallet;
    /// What a donor pays in for one envelope.
    uint256 public immutable denomination;
    /// What one envelope is worth inside the box, after the platform fee.
    uint256 public immutable noteValue;

    uint256[LEVELS] public zeros;
    uint256[LEVELS] public filledSubtrees;
    uint256[ROOT_HISTORY] public roots;
    uint32 public currentRootIndex;
    uint32 public nextIndex;

    mapping(uint256 => bool) public spent;

    event Deposit(uint256 indexed commitment, uint32 leafIndex, bytes envelope);
    event Withdrawal(address indexed recipient, address indexed relayer, uint256 amount, uint256 fee, uint256[4] nullifiers);

    constructor(IERC20 token_, IAnonBoxVerifier verifier_, address platformWallet_, uint256 denomination_) {
        require(address(token_) != address(0), "bad token");
        require(address(verifier_) != address(0), "bad verifier");
        require(platformWallet_ != address(0), "bad platform");
        require(denomination_ > 0, "bad denomination");
        token = token_;
        verifier = verifier_;
        platformWallet = platformWallet_;
        denomination = denomination_;
        noteValue = denomination_ - (denomination_ * PLATFORM_FEE_BPS) / 10000;

        uint256 z = uint256(keccak256("peremech.anonbox")) % FIELD;
        for (uint32 i = 0; i < LEVELS; i++) {
            zeros[i] = z;
            filledSubtrees[i] = z;
            z = PoseidonT3.hash([z, z]);
        }
        roots[0] = z;
    }

    // ---------------------------------------------------------------- deposit

    /// Where a donor sends exactly `denomination` for this envelope. The address is
    /// bound to the commitment and the letter, so nobody can claim that money for a
    /// different envelope.
    function dropAddress(uint256 commitment, bytes calldata envelope) public view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _dropSalt(commitment, envelope), keccak256(type(Drop).creationCode))
        );
        return address(uint160(uint256(h)));
    }

    /// Put the envelope whose money already sits at its drop address into the box.
    /// Open to anyone: the result is the same whoever calls.
    function collect(uint256 commitment, bytes calldata envelope) external {
        _collect(commitment, envelope);
    }

    function _collect(uint256 commitment, bytes calldata envelope) internal {
        require(commitment < FIELD, "bad commitment");
        require(envelope.length > 0 && envelope.length <= MAX_ENVELOPE, "bad envelope");

        uint256 before = token.balanceOf(address(this));
        new Drop{salt: _dropSalt(commitment, envelope)}();
        require(token.balanceOf(address(this)) - before == denomination, "wrong amount");

        uint256 fee = denomination - noteValue;
        require(token.transfer(platformWallet, fee), "fee failed");

        uint32 index = _insert(commitment);
        emit Deposit(commitment, index, envelope);
    }

    /// Deposit straight from the donor's custody account in one transaction: deliver
    /// the withdrawal the donor signed to this envelope's drop address, then collect it.
    /// Either both happen or neither, so money can never get stuck half-way.
    /// Open to anyone and gives the caller no power: the donor's signature fixes the
    /// destination and the amount, and a fake custody simply fails the amount check.
    function depositFromCustody(
        ICustody custody,
        bytes32 user,
        uint256 commitment,
        bytes calldata envelope,
        uint256 keyIndex,
        WebAuthn.Auth calldata auth
    ) external {
        custody.withdraw(user, dropAddress(commitment, envelope), denomination, keyIndex, auth);
        _collect(commitment, envelope);
    }

    function _dropSalt(uint256 commitment, bytes calldata envelope) internal pure returns (bytes32) {
        return keccak256(abi.encode(commitment, keccak256(envelope)));
    }

    // ---------------------------------------------------------------- withdrawal

    /// Take up to MAX_INPUTS envelopes out at once. Empty slots have a zero nullifier.
    function withdraw(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256 root,
        uint256[4] calldata nullifiers,
        address recipient,
        address relayer,
        uint256 fee
    ) external {
        require(recipient != address(0), "bad recipient");
        require(isKnownRoot(root), "unknown root");

        uint256 count;
        for (uint256 i = 0; i < MAX_INPUTS; i++) {
            uint256 n = nullifiers[i];
            if (n == 0) continue;
            require(n < FIELD, "bad nullifier");
            require(!spent[n], "already taken");
            spent[n] = true;
            count++;
        }
        require(count > 0, "nothing to take");
        uint256 amount = count * noteValue;
        require(fee <= amount, "fee too high");

        uint256[8] memory pub = [
            root,
            nullifiers[0],
            nullifiers[1],
            nullifiers[2],
            nullifiers[3],
            uint256(uint160(recipient)),
            uint256(uint160(relayer)),
            fee
        ];
        require(verifier.verifyProof(a, b, c, pub), "bad proof");

        require(token.transfer(recipient, amount - fee), "payout failed");
        if (fee > 0) {
            require(relayer != address(0), "bad relayer");
            require(token.transfer(relayer, fee), "relayer fee failed");
        }
        emit Withdrawal(recipient, relayer, amount, fee, nullifiers);
    }

    // ---------------------------------------------------------------- tree

    function _insert(uint256 leaf) internal returns (uint32 index) {
        index = nextIndex;
        require(index < uint32(1) << LEVELS, "box is full");
        uint256 cur = leaf;
        uint32 idx = index;
        for (uint32 i = 0; i < LEVELS; i++) {
            if (idx % 2 == 0) {
                filledSubtrees[i] = cur;
                cur = PoseidonT3.hash([cur, zeros[i]]);
            } else {
                cur = PoseidonT3.hash([filledSubtrees[i], cur]);
            }
            idx /= 2;
        }
        uint32 next = (currentRootIndex + 1) % ROOT_HISTORY;
        currentRootIndex = next;
        roots[next] = cur;
        nextIndex = index + 1;
    }

    /// A proof may be built against a slightly older root: new envelopes keep arriving
    /// while the recipient's phone is computing it.
    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        uint32 i = currentRootIndex;
        do {
            if (roots[i] == root) return true;
            i = i == 0 ? ROOT_HISTORY - 1 : i - 1;
        } while (i != currentRootIndex);
        return false;
    }

    function lastRoot() external view returns (uint256) {
        return roots[currentRootIndex];
    }
}

/// A one-envelope drop point. Deployed deterministically (CREATE2) by the box; its
/// only job is to hand the money sent to it over to the box, once.
contract Drop {
    constructor() {
        AnonBox box = AnonBox(msg.sender);
        IERC20 t = box.token();
        uint256 amount = t.balanceOf(address(this));
        if (amount > 0) {
            require(t.transfer(msg.sender, amount), "drop failed");
        }
    }
}
