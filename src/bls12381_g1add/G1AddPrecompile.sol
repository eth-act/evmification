// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title G1AddPrecompile
/// @notice Wrapper around the EIP-2537 G1ADD precompile (address 0x0b).
library G1AddPrecompile {
    /// @notice Adds two G1 points using the native precompile.
    /// @param input 256 bytes: two G1 points in EIP-2537 format.
    /// @return output 128 bytes: the resulting G1 point.
    function g1Add(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(128);
        assembly {
            let success := staticcall(gas(), 0x0b, add(input, 0x20), mload(input), add(output, 0x20), 128)
            if iszero(success) { revert(0, 0) }
        }
    }
}
