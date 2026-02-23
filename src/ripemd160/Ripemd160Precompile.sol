// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Ripemd160Precompile
/// @notice Wrapper around the EVM RIPEMD-160 precompile (address 0x03).
/// @dev The precompile returns 32 bytes (left-padded with 12 zero bytes).
library Ripemd160Precompile {
    /// @notice Computes RIPEMD-160 hash using the EVM precompile.
    /// @param data The input data to hash.
    /// @return result The 20-byte RIPEMD-160 digest.
    function hash(bytes memory data) internal view returns (bytes20 result) {
        assembly {
            let len := mload(data)
            let ptr := add(data, 0x20)
            let outBuf := mload(0x40)
            let success := staticcall(gas(), 0x03, ptr, len, outBuf, 0x20)
            if iszero(success) { revert(0, 0) }
            // Precompile returns 32 bytes: 12 zero bytes + 20-byte hash
            // bytes20 is left-aligned, so shift left by 12 bytes (96 bits)
            result := shl(96, mload(outBuf))
        }
    }
}
