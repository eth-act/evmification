// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Blake2fPrecompile
/// @notice Wrapper around the EVM BLAKE2b F compression precompile (address 0x09, EIP-152).
/// @dev Encodes inputs per EIP-152 and staticcalls the precompile.
library Blake2fPrecompile {
    /// @notice Computes the BLAKE2b F compression function using the EVM precompile.
    /// @param rounds Number of rounds (0..2^32-1).
    /// @param h State vector (8 uint64 values).
    /// @param m Message block (16 uint64 values).
    /// @param t Offset counters (2 uint64 values).
    /// @param finalBlock True if this is the final block.
    /// @return result The updated state vector (8 uint64 values).
    function compress(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) internal view returns (uint64[8] memory result) {
        assembly {
            // Allocate 213-byte buffer
            let buf := mload(0x40)
            mstore(0x40, add(buf, 256)) // overallocate for alignment

            // Helper: byte-swap uint64 (big-endian <-> little-endian)
            function swap64(x) -> r {
                x := and(x, 0xffffffffffffffff)
                x := or(shl(8, and(x, 0x00FF00FF00FF00FF)), shr(8, and(x, 0xFF00FF00FF00FF00)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                r := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
            }

            // Write rounds as 4 big-endian bytes
            mstore8(buf, shr(24, rounds))
            mstore8(add(buf, 1), shr(16, rounds))
            mstore8(add(buf, 2), shr(8, rounds))
            mstore8(add(buf, 3), rounds)

            // Write h[0..7] as little-endian uint64s (8 bytes each) starting at offset 4
            let ptr := add(buf, 4)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let val := swap64(mload(add(h, mul(i, 0x20))))
                // Write 8 bytes
                mstore8(ptr, shr(56, val))
                mstore8(add(ptr, 1), shr(48, val))
                mstore8(add(ptr, 2), shr(40, val))
                mstore8(add(ptr, 3), shr(32, val))
                mstore8(add(ptr, 4), shr(24, val))
                mstore8(add(ptr, 5), shr(16, val))
                mstore8(add(ptr, 6), shr(8, val))
                mstore8(add(ptr, 7), val)
                ptr := add(ptr, 8)
            }

            // Write m[0..15] as little-endian uint64s starting at offset 68
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let val := swap64(mload(add(m, mul(i, 0x20))))
                mstore8(ptr, shr(56, val))
                mstore8(add(ptr, 1), shr(48, val))
                mstore8(add(ptr, 2), shr(40, val))
                mstore8(add(ptr, 3), shr(32, val))
                mstore8(add(ptr, 4), shr(24, val))
                mstore8(add(ptr, 5), shr(16, val))
                mstore8(add(ptr, 6), shr(8, val))
                mstore8(add(ptr, 7), val)
                ptr := add(ptr, 8)
            }

            // Write t[0..1] as little-endian uint64s starting at offset 196
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                let val := swap64(mload(add(t, mul(i, 0x20))))
                mstore8(ptr, shr(56, val))
                mstore8(add(ptr, 1), shr(48, val))
                mstore8(add(ptr, 2), shr(40, val))
                mstore8(add(ptr, 3), shr(32, val))
                mstore8(add(ptr, 4), shr(24, val))
                mstore8(add(ptr, 5), shr(16, val))
                mstore8(add(ptr, 6), shr(8, val))
                mstore8(add(ptr, 7), val)
                ptr := add(ptr, 8)
            }

            // Write finalBlock as 1 byte at offset 212
            mstore8(add(buf, 212), finalBlock)

            // Call precompile 0x09
            let outBuf := mload(0x40)
            mstore(0x40, add(outBuf, 64))
            let success := staticcall(gas(), 0x09, buf, 213, outBuf, 64)
            if iszero(success) { revert(0, 0) }

            // Parse 64-byte output back into uint64[8] (byte-swap each LE uint64)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let off := add(outBuf, mul(i, 8))
                let val := shr(192, mload(off))
                val := swap64(val)
                mstore(add(result, mul(i, 0x20)), val)
            }
        }
    }

    /// @notice Computes the BLAKE2b F compression function from raw 213-byte EIP-152 input.
    /// @param input 213 bytes in EIP-152 format.
    /// @return output 64 bytes of output.
    function compress(bytes memory input) internal view returns (bytes memory output) {
        require(input.length == 213, "Blake2fPrecompile: invalid input length");
        output = new bytes(64);
        assembly {
            let inPtr := add(input, 0x20)
            let outPtr := add(output, 0x20)
            let success := staticcall(gas(), 0x09, inPtr, 213, outPtr, 64)
            if iszero(success) { revert(0, 0) }
        }
    }
}
