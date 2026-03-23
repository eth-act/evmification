// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title PairingPrecompile
/// @notice Wrapper around the native EIP-2537 pairing precompile (address 0x0f).
library PairingPrecompile {
    /// @notice Calls the native pairing precompile.
    /// @param input k * 384 bytes: k pairs of (G1(128) || G2(256)).
    /// @return output 32 bytes: 0x..01 if pairing check passes, else 0x..00.
    function pairing(bytes memory input) internal view returns (bytes memory output) {
        output = new bytes(32);
        assembly {
            let success := staticcall(gas(), 0x0f, add(input, 0x20), mload(input), add(output, 0x20), 32)
            if iszero(success) { revert(0, 0) }
        }
    }
}
