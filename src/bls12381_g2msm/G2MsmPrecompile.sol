// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title G2MsmPrecompile
/// @notice Wrapper around the EIP-2537 G2MSM precompile (address 0x0e).
library G2MsmPrecompile {
    /// @notice Computes G2 multi-scalar multiplication using the native precompile.
    /// @param input k * 288 bytes: k chunks of (G2_point(256) || scalar(32)).
    /// @return output 256 bytes: the resulting G2 point.
    function g2Msm(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(256);
        assembly {
            let success := staticcall(gas(), 0x0e, add(input, 0x20), mload(input), add(output, 0x20), 256)
            if iszero(success) { revert(0, 0) }
        }
    }
}
