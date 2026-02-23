// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ModexpMontgomery} from "../../src/modexp/ModexpMontgomery.sol";

/// @title RSAVerifyMontgomery
/// @notice PKCS#1 v1.5 SHA-256 RSA signature verification using readable Montgomery modexp.
library RSAVerifyMontgomery {
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
        uint256 emLen = em.length;

        // Step 2: Verify PKCS#1 v1.5 encoding
        // Format: 0x00 || 0x01 || PS (0xFF bytes) || 0x00 || DigestInfo || Hash

        // em must be at least: 2 (0x00 0x01) + 8 (min PS) + 1 (0x00) + DigestInfo + 32 (hash)
        if (emLen < 0x3D) return false;

        // Determine DigestInfo variant by checking the sequence length byte
        bytes32 params;
        bytes32 mask;
        uint256 offset;

        if (bytes1(_unsafeReadBytes32(em, emLen - 0x32)) == 0x31) {
            // Explicit NULL parameter variant
            offset = 0x34;
            params = 0x003031300d060960864801650304020105000420000000000000000000000000;
            mask = 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000;
        } else if (bytes1(_unsafeReadBytes32(em, emLen - 0x30)) == 0x2F) {
            // Implicit NULL parameter variant
            offset = 0x32;
            params = 0x00302f300b060960864801650304020104200000000000000000000000000000;
            mask = 0xffffffffffffffffffffffffffffffffffff0000000000000000000000000000;
        } else {
            return false;
        }

        uint256 paddingEnd = emLen - offset;

        // Check PS (padding) - all 0xFF bytes, using unsafe reads to skip bounds checks
        for (uint256 i = 2; i < paddingEnd; ++i) {
            if (bytes1(_unsafeReadBytes32(em, i)) != 0xFF) {
                return false;
            }
        }

        // Step 3: Verify prefix, DigestInfo, and hash in a single return
        bytes32 messageHash = sha256(message);
        return
            bytes2(0x0001) == bytes2(_unsafeReadBytes32(em, 0x00)) &&
            params == _unsafeReadBytes32(em, paddingEnd) & mask &&
            messageHash == _unsafeReadBytes32(em, emLen - 0x20);
    }

    /// @dev Reads a bytes32 from a bytes array without bounds checking.
    function _unsafeReadBytes32(bytes memory array, uint256 offset) private pure returns (bytes32 result) {
        assembly ("memory-safe") {
            result := mload(add(add(array, 0x20), offset))
        }
    }
}
