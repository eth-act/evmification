// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Sha256Precompile
/// @notice Wrapper around the EVM SHA-256 precompile (address 0x02).
library Sha256Precompile {
    /// @notice Computes SHA-256 hash using the EVM precompile.
    /// @param data The input data to hash.
    /// @return result The 32-byte SHA-256 digest.
    function hash(bytes memory data) internal view returns (bytes32 result) {
        assembly {
            let len := mload(data)
            let ptr := add(data, 0x20)
            let outBuf := mload(0x40)
            let success := staticcall(gas(), 0x02, ptr, len, outBuf, 0x20)
            if iszero(success) { revert(0, 0) }
            result := mload(outBuf)
        }
    }
}
