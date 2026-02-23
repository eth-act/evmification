// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title PointEvalPrecompile
/// @notice Wrapper around the EIP-4844 point evaluation precompile (address 0x0a).
library PointEvalPrecompile {
    /// @notice Verifies a KZG proof using the EVM precompile.
    /// @param input 192-byte input: versioned_hash (32) || z (32) || y (32) || commitment (48) || proof (48).
    /// @return fieldElementsPerBlob Always 4096.
    /// @return blsModulus The BLS12-381 scalar field modulus.
    function verify(bytes memory input) internal view returns (uint256 fieldElementsPerBlob, uint256 blsModulus) {
        assembly {
            let len := mload(input)
            let ptr := add(input, 0x20)
            let outBuf := mload(0x40)
            let success := staticcall(gas(), 0x0a, ptr, len, outBuf, 0x40)
            if iszero(success) { revert(0, 0) }
            fieldElementsPerBlob := mload(outBuf)
            blsModulus := mload(add(outBuf, 0x20))
        }
    }
}
