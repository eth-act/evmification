// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ModexpMontgomery} from "./ModexpMontgomery.sol";
import {ModexpBarrett} from "./ModexpBarrett.sol";

/// @title Modexp
/// @notice Modular exponentiation for any modulus.
/// @dev Uses Montgomery multiplication for odd moduli (faster) and
///      Barrett reduction for even moduli.
library Modexp {
    /// @notice Computes base^exp mod modulus.
    /// @param base The base value (big-endian bytes).
    /// @param exponent The exponent value (big-endian bytes).
    /// @param modulus The modulus value (big-endian bytes).
    /// @return result The result (big-endian bytes, same length as modulus).
    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal pure returns (bytes memory result) {
        if (modulus.length == 0) return new bytes(0);

        // Check if modulus is odd (last byte has bit 0 set)
        if (uint8(modulus[modulus.length - 1]) & 1 == 1) {
            return ModexpMontgomery.modexp(base, exponent, modulus);
        } else {
            return ModexpBarrett.modexp(base, exponent, modulus);
        }
    }
}
