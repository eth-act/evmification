// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ModexpPrecompile
/// @notice Wrapper around the EVM modular exponentiation precompile (address 0x05).
/// @dev Encodes inputs per EIP-198 and staticcalls the precompile.
library ModexpPrecompile {
    /// @notice Computes base^exp mod modulus using the EVM precompile.
    /// @param base The base value (big-endian bytes).
    /// @param exponent The exponent value (big-endian bytes).
    /// @param modulus The modulus value (big-endian bytes).
    /// @return result The result of base^exp mod modulus (big-endian bytes, same length as modulus).
    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(
            uint256(base.length),
            uint256(exponent.length),
            uint256(modulus.length),
            base,
            exponent,
            modulus
        );

        result = new bytes(modulus.length);

        assembly {
            let success := staticcall(
                gas(),
                0x05,
                add(input, 0x20),
                mload(input),
                add(result, 0x20),
                mload(modulus)
            )
            if iszero(success) {
                revert(0, 0)
            }
        }
    }
}
