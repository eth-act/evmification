// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Modexp} from "./Modexp.sol";

/// @title ModexpDeployed
/// @notice Drop-in replacement for the modular exponentiation precompile (0x05).
/// @dev Deploy once, then staticcall with raw EIP-198 input.
///      Returns raw result bytes — identical interface to the native precompile.
///
///      Input format (EIP-198):
///        [Bsize (32 bytes)] [Esize (32 bytes)] [Msize (32 bytes)]
///        [base (Bsize bytes)] [exponent (Esize bytes)] [modulus (Msize bytes)]
///      Output: Msize bytes (big-endian result, same length as modulus).
contract ModexpDeployed {
    fallback() external {
        bytes memory input = msg.data;
        uint256 bSize;
        uint256 eSize;
        uint256 mSize;
        assembly {
            let ptr := add(input, 0x20)
            bSize := mload(ptr)
            eSize := mload(add(ptr, 0x20))
            mSize := mload(add(ptr, 0x40))
        }

        bytes memory base = new bytes(bSize);
        bytes memory exponent = new bytes(eSize);
        bytes memory modulus = new bytes(mSize);
        assembly {
            let src := add(add(input, 0x20), 0x60)
            // Copy base
            let dst := add(base, 0x20)
            for { let i := 0 } lt(i, bSize) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
            src := add(src, bSize)
            // Copy exponent
            dst := add(exponent, 0x20)
            for { let i := 0 } lt(i, eSize) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
            src := add(src, eSize)
            // Copy modulus
            dst := add(modulus, 0x20)
            for { let i := 0 } lt(i, mSize) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }

        bytes memory result = Modexp.modexp(base, exponent, modulus);
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
