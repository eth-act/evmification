// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title G1MsmPrecompile
/// @notice Wrapper around the EIP-2537 G1MSM precompile (address 0x0c).
library G1MsmPrecompile {
    /// @notice Computes multi-scalar multiplication using the native precompile.
    /// @param input k * 160 bytes: k pairs of (G1 point (128 bytes) || scalar (32 bytes)).
    /// @return output 128 bytes: the resulting G1 point.
    function g1Msm(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(128);
        assembly {
            let success := staticcall(gas(), 0x0c, add(input, 0x20), mload(input), add(output, 0x20), 128)
            if iszero(success) { revert(0, 0) }
        }
    }
}
