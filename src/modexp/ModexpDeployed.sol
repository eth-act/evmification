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
        uint256 bSize;
        uint256 eSize;
        uint256 mSize;
        assembly {
            // calldataload zero-pads past the end, matching native precompile behavior
            bSize := calldataload(0x00)
            eSize := calldataload(0x20)
            mSize := calldataload(0x40)
            // EIP-7823: revert if any operand exceeds 1024 bytes
            if or(gt(bSize, 1024), or(gt(eSize, 1024), gt(mSize, 1024))) { revert(0, 0) }
        }

        // new bytes() is zero-initialized, so truncated calldata is implicitly zero-padded
        bytes memory base = new bytes(bSize);
        bytes memory exponent = new bytes(eSize);
        bytes memory modulus = new bytes(mSize);
        assembly {
            let cdLen := calldatasize()

            // Copy base (zero-pad if calldata is truncated)
            let off := 0x60
            let avail := 0
            if gt(cdLen, off) { avail := sub(cdLen, off) }
            if gt(avail, bSize) { avail := bSize }
            if gt(avail, 0) { calldatacopy(add(base, 0x20), off, avail) }

            // Copy exponent
            off := add(0x60, bSize)
            avail := 0
            if gt(cdLen, off) { avail := sub(cdLen, off) }
            if gt(avail, eSize) { avail := eSize }
            if gt(avail, 0) { calldatacopy(add(exponent, 0x20), off, avail) }

            // Copy modulus
            off := add(off, eSize)
            avail := 0
            if gt(cdLen, off) { avail := sub(cdLen, off) }
            if gt(avail, mSize) { avail := mSize }
            if gt(avail, 0) { calldatacopy(add(modulus, 0x20), off, avail) }
        }

        bytes memory result = Modexp.modexp(base, exponent, modulus);
        assembly {
            return(add(result, 0x20), mload(result))
        }
    }
}
