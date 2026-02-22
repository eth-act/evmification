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
        uint256 mLen = modulus.length;

        // Encode call args in result and reuse the buffer for the output
        result = abi.encodePacked(
            uint256(base.length),
            uint256(exponent.length),
            uint256(mLen),
            base,
            exponent,
            modulus
        );

        assembly {
            let dataPtr := add(result, 0x20)
            // Write result on top of args to avoid allocating extra memory
            let success := staticcall(gas(), 0x05, dataPtr, mload(result), dataPtr, mLen)
            if iszero(success) {
                revert(0, 0)
            }
            // Overwrite the length (result.length >= mLen is guaranteed)
            mstore(result, mLen)
            // Set the memory pointer after the returned data
            mstore(0x40, add(dataPtr, mLen))
        }
    }
}
