// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title MapFpToG2Precompile
/// @notice Wrapper around the EIP-2537 MAP_FP_TO_G2 precompile (address 0x11).
library MapFpToG2Precompile {
    /// @notice Maps an Fp2 element to a G2 point using the native precompile.
    /// @param input 128 bytes: Fp2 element (two 64-byte padded Fp elements).
    /// @return output 256 bytes: G2 point in EIP-2537 format.
    function mapToG2(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(256);
        assembly {
            let success := staticcall(gas(), 0x11, add(input, 0x20), mload(input), add(output, 0x20), 256)
            if iszero(success) { revert(0, 0) }
        }
    }
}
