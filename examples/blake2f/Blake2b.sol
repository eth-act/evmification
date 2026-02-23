// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Blake2fPrecompile} from "../../src/blake2f/Blake2fPrecompile.sol";

/// @title Blake2b
/// @notice BLAKE2b hash using the EVM F compression precompile (EIP-152).
library Blake2b {
    /// @notice Computes BLAKE2b hash of `data` with the given output length.
    /// @param data Input bytes.
    /// @param outlen Output length in bytes (1-64).
    /// @return digest The hash digest.
    function hash(bytes memory data, uint64 outlen) internal view returns (bytes memory digest) {
        require(outlen >= 1 && outlen <= 64, "Blake2b: invalid outlen");

        // IV constants
        uint64[8] memory h = [
            uint64(0x6a09e667f3bcc908),
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        ];

        // Parameter block XOR: h[0] ^= 0x01010000 ^ outlen
        h[0] ^= 0x01010000 ^ outlen;

        uint256 dataLen = data.length;
        uint256 offset = 0;
        uint64[2] memory t;

        // Process full 128-byte blocks (all but the last block)
        while (offset + 128 < dataLen) {
            uint64[16] memory m = _loadBlock(data, offset);
            offset += 128;
            t[0] += 128;
            h = Blake2fPrecompile.compress(12, h, m, t, false);
        }

        // Final block: remaining bytes padded with zeros
        uint256 remaining = dataLen - offset;
        uint64[16] memory mFinal = _loadBlockPadded(data, offset, remaining);
        t[0] += uint64(remaining);
        h = Blake2fPrecompile.compress(12, h, mFinal, t, true);

        // Encode h as little-endian bytes and truncate to outlen
        digest = _encodeOutput(h, outlen);
    }

    /// @dev Loads a full 128-byte block from data at the given offset as 16 little-endian uint64s.
    function _loadBlock(bytes memory data, uint256 offset) private pure returns (uint64[16] memory m) {
        assembly {
            let src := add(add(data, 0x20), offset)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let chunk := mload(add(src, mul(i, 8)))
                // Extract top 8 bytes and byte-swap to little-endian
                let val := shr(192, chunk)
                // swap64
                val := or(shl(8, and(val, 0x00FF00FF00FF00FF)), shr(8, and(val, 0xFF00FF00FF00FF00)))
                val := or(shl(16, and(val, 0x0000FFFF0000FFFF)), shr(16, and(val, 0xFFFF0000FFFF0000)))
                val := or(shl(32, and(val, 0x00000000FFFFFFFF)), shr(32, and(val, 0xFFFFFFFF00000000)))
                mstore(add(m, mul(i, 0x20)), val)
            }
        }
    }

    /// @dev Loads a partial block (0..128 bytes) zero-padded to 128 bytes as 16 LE uint64s.
    function _loadBlockPadded(bytes memory data, uint256 offset, uint256 len)
        private
        pure
        returns (uint64[16] memory m)
    {
        // Copy remaining bytes into a 128-byte buffer, zero-padded
        bytes memory buf = new bytes(128);
        assembly {
            let src := add(add(data, 0x20), offset)
            let dst := add(buf, 0x20)
            // Copy len bytes
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore8(add(dst, i), byte(0, mload(add(src, i))))
            }
        }
        m = _loadBlock(buf, 0);
    }

    /// @dev Encodes the state vector h as little-endian bytes, truncated to outlen.
    function _encodeOutput(uint64[8] memory h, uint64 outlen) private pure returns (bytes memory out) {
        out = new bytes(outlen);
        assembly {
            let dst := add(out, 0x20)
            let remaining := outlen
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                if iszero(remaining) { break }
                let val := mload(add(h, mul(i, 0x20)))
                // Write as little-endian bytes
                let bytesToWrite := remaining
                if gt(bytesToWrite, 8) { bytesToWrite := 8 }
                for { let b := 0 } lt(b, bytesToWrite) { b := add(b, 1) } {
                    mstore8(add(dst, add(mul(i, 8), b)), and(shr(mul(b, 8), val), 0xff))
                }
                remaining := sub(remaining, bytesToWrite)
            }
        }
    }
}
