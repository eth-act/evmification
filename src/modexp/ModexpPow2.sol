// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ModexpPow2
/// @notice Modular exponentiation with power-of-2 moduli (base^exp mod 2^kBits).
library ModexpPow2 {
    /// @notice Computes base^exponent mod 2^kBits.
    /// @param base The base value (big-endian bytes).
    /// @param exponent The exponent value (big-endian bytes).
    /// @param kBits The exponent of the power-of-2 modulus.
    /// @return result The result (big-endian bytes, length ceil(kBits/8)).
    function modexp(bytes memory base, bytes memory exponent, uint256 kBits)
        internal pure returns (bytes memory result)
    {
        revert("not implemented");
    }
}
