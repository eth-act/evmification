// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title MapFpToG1Precompile
/// @notice Wrapper around the EIP-2537 MAP_FP_TO_G1 precompile (address 0x10).
library MapFpToG1Precompile {
    /// @notice Maps a field element to a G1 point using the native precompile.
    /// @param input 64 bytes: Fp element (48 bytes, left-padded to 64).
    /// @return output 128 bytes: G1 point in EIP-2537 format.
    function mapToG1(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(128);
        assembly {
            let success := staticcall(gas(), 0x10, add(input, 0x20), mload(input), add(output, 0x20), 128)
            if iszero(success) { revert(0, 0) }
        }
    }
}
