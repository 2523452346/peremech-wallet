// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Encodes 32 bytes as unpadded base64url — exactly 43 characters.
/// Needed because the browser embeds our challenge in clientDataJSON in that form.
library Base64URL {
    bytes internal constant TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    function encode32(bytes32 data) internal pure returns (string memory) {
        bytes memory table = TABLE;
        bytes memory out = new bytes(43);

        uint256 j = 0;
        for (uint256 i = 0; i < 30; i += 3) {
            uint256 v = (uint256(uint8(data[i])) << 16) | (uint256(uint8(data[i + 1])) << 8)
                | uint256(uint8(data[i + 2]));
            out[j++] = table[(v >> 18) & 0x3f];
            out[j++] = table[(v >> 12) & 0x3f];
            out[j++] = table[(v >> 6) & 0x3f];
            out[j++] = table[v & 0x3f];
        }

        // Tail: 2 bytes become 3 characters, padded with two zero bits.
        uint256 t = (uint256(uint8(data[30])) << 8) | uint256(uint8(data[31]));
        out[40] = table[(t >> 10) & 0x3f];
        out[41] = table[(t >> 4) & 0x3f];
        out[42] = table[(t << 2) & 0x3f];

        return string(out);
    }
}

/// Verifies a passkey (WebAuthn) signature on chain.
///
/// The private key lives inside the secure element of the user's device and never
/// leaves it; only the signature does. Here we check that signature against the
/// public key recorded for the user.
///
/// The device does not sign our challenge directly. It signs
/// sha256(authenticatorData ‖ sha256(clientDataJSON)), where clientDataJSON is text
/// produced by the browser that contains our challenge. So we first make sure the
/// text really carries our challenge, and only then verify the signature itself.
library WebAuthn {
    struct Auth {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeIndex; // offset of `"challenge":"` inside clientDataJSON
        uint256 typeIndex; // offset of `"type":"` inside clientDataJSON
        uint256 r;
        uint256 s;
    }

    /// RIP-7212 precompile: verifies a P-256 signature for roughly 3450 gas.
    address internal constant P256_VERIFIER = address(0x100);

    bytes1 internal constant FLAG_USER_PRESENT = 0x01; // a human touched the device
    bytes1 internal constant FLAG_USER_VERIFIED = 0x04; // and proved who they are (biometrics or PIN)

    /// Half of the P-256 curve order. A signature with a higher s is the mirror image
    /// of the same signature; rejecting those keeps one command from being replayed
    /// under a second, equally valid signature.
    uint256 internal constant P256_HALF_N =
        0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;

    /// challenge — what the user signed: a donation or a withdrawal command.
    /// x, y — the public key recorded for that user in the custody contract.
    function verify(bytes32 challenge, Auth memory auth, uint256 x, uint256 y) internal view returns (bool) {
        if (auth.s == 0 || auth.s > P256_HALF_N) return false;

        bytes memory clientData = bytes(auth.clientDataJSON);

        // This must be an authentication assertion, not a registration one.
        if (!_matchesAt(clientData, auth.typeIndex, '"type":"webauthn.get"')) return false;

        // And it must carry our command, not someone else's.
        if (!_matchesAt(clientData, auth.challengeIndex, string.concat('"challenge":"', Base64URL.encode32(challenge), '"')))
        {
            return false;
        }

        // The device attests that a human was present and verified.
        if (auth.authenticatorData.length < 37) return false;
        bytes1 flags = auth.authenticatorData[32];
        if (flags & FLAG_USER_PRESENT != FLAG_USER_PRESENT) return false;
        if (flags & FLAG_USER_VERIFIED != FLAG_USER_VERIFIED) return false;

        bytes32 message = sha256(abi.encodePacked(auth.authenticatorData, sha256(clientData)));

        (bool ok, bytes memory ret) = P256_VERIFIER.staticcall(abi.encode(message, auth.r, auth.s, x, y));
        // The precompile returns 32 bytes of one for a valid signature, empty otherwise.
        return ok && ret.length == 32 && abi.decode(ret, (uint256)) == 1;
    }

    function _matchesAt(bytes memory data, uint256 offset, string memory expected) private pure returns (bool) {
        bytes memory want = bytes(expected);
        if (offset > data.length || data.length - offset < want.length) return false;
        for (uint256 i = 0; i < want.length; i++) {
            if (data[offset + i] != want[i]) return false;
        }
        return true;
    }
}
