// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ModexpMontgomery} from "./ModexpMontgomery.sol";

/// @title RSAVerifyMontgomery
/// @notice PKCS#1 v1.5 SHA-256 RSA signature verification using Montgomery modexp.
library RSAVerifyMontgomery {
    /// @dev ASN.1 DigestInfo prefix for SHA-256 per RFC 8017 Section 9.2 Note 1.
    bytes constant DIGEST_INFO_PREFIX = hex"3031300d060960864801650304020105000420";

    /// @notice Verifies an RSA PKCS#1 v1.5 SHA-256 signature.
    /// @param modulus RSA public key modulus (n), big-endian.
    /// @param exponent RSA public key exponent (e), big-endian.
    /// @param message The signed message.
    /// @param signature The signature to verify, big-endian.
    /// @return valid True if the signature is valid.
    function verify(
        bytes memory modulus,
        bytes memory exponent,
        bytes memory message,
        bytes memory signature
    ) internal view returns (bool valid) {
        // Step 1: Recover the padded hash via modexp: signature^e mod n
        bytes memory em = ModexpMontgomery.modexp(signature, exponent, modulus);

        // Step 2: Verify PKCS#1 v1.5 encoding
        // Format: 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || DigestInfo || Hash
        uint256 emLen = em.length;
        uint256 digestInfoLen = DIGEST_INFO_PREFIX.length; // 19 bytes
        uint256 hashLen = 32; // SHA-256
        uint256 tLen = digestInfoLen + hashLen; // 51 bytes

        // em must be at least: 1 (0x00) + 1 (0x01) + 8 (min PS) + 1 (0x00) + tLen
        if (emLen < 11 + tLen) return false;

        // Check 0x00 0x01 prefix
        if (uint8(em[0]) != 0x00) return false;
        if (uint8(em[1]) != 0x01) return false;

        // Check PS (padding) - all 0xFF bytes
        uint256 psEnd = emLen - tLen - 1;
        for (uint256 i = 2; i < psEnd; i++) {
            if (uint8(em[i]) != 0xFF) return false;
        }

        // Check 0x00 separator
        if (uint8(em[psEnd]) != 0x00) return false;

        // Check DigestInfo prefix
        uint256 digestInfoStart = psEnd + 1;
        for (uint256 i = 0; i < digestInfoLen; i++) {
            if (em[digestInfoStart + i] != DIGEST_INFO_PREFIX[i]) return false;
        }

        // Step 3: Extract hash from em and compare with sha256(message)
        bytes32 messageHash = sha256(message);
        bytes32 emHash;
        uint256 hashStart = digestInfoStart + digestInfoLen;
        assembly {
            emHash := mload(add(add(em, 0x20), hashStart))
        }

        return messageHash == emHash;
    }
}
