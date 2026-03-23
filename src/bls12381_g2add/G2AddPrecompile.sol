// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title G2AddPrecompile
/// @notice Wrapper around the EIP-2537 G2ADD precompile (address 0x0d).
library G2AddPrecompile {
    /// @notice Adds two G2 points using the native precompile.
    /// @param input 512 bytes: two G2 points in EIP-2537 format.
    /// @return output 256 bytes: the resulting G2 point.
    function g2Add(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(256);
        assembly {
            let success := staticcall(gas(), 0x0d, add(input, 0x20), mload(input), add(output, 0x20), 256)
            if iszero(success) { revert(0, 0) }
        }
    }
}
