// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library ModexpMontgomery {
    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bytes memory result) {
        // TODO: implement
        result = new bytes(modulus.length);
    }
}
