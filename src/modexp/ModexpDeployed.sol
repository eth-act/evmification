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

        // Fast path: all operands fit in a single uint256 — pure stack arithmetic
        if (bSize <= 32 && eSize <= 32 && mSize <= 32) {
            assembly {
                // calldataload right-aligns values shorter than 32 bytes via
                // shr, giving us the correct big-endian uint256 value.
                let b := shr(mul(sub(32, bSize), 8), calldataload(0x60))
                let e := shr(mul(sub(32, eSize), 8), calldataload(add(0x60, bSize)))
                let m := shr(mul(sub(32, mSize), 8), calldataload(add(add(0x60, bSize), eSize)))

                let r := 0
                if gt(m, 1) {
                    r := 1
                    b := mod(b, m)
                    for {} gt(e, 0) {} {
                        if and(e, 1) { r := mulmod(r, b, m) }
                        b := mulmod(b, b, m)
                        e := shr(1, e)
                    }
                }

                // Return mSize bytes (big-endian, left-padded with zeros)
                mstore(0x00, r)
                return(sub(0x20, mSize), mSize)
            }
        }

        // Fast paths for trivial inputs: exp=0, base=0, base=1.
        // Avoids expensive Barrett/Montgomery setup.
        assembly {
            // Returns 1 if any byte in calldata[start..end) is nonzero.
            function cdRangeNonZero(start, end) -> nz {
                for { let p := start } lt(p, end) { p := add(p, 0x20) } {
                    let w := calldataload(p)
                    let rem := sub(end, p)
                    if lt(rem, 0x20) { w := shr(mul(sub(0x20, rem), 8), w) }
                    if w { nz := 1 p := end }
                }
            }

            // Returns 1 if the sz-byte big-endian number at calldata[off..] is > 1.
            function isGt1(off, sz) -> r {
                if gt(sz, 1) { r := cdRangeNonZero(off, add(off, sub(sz, 1))) }
                if and(iszero(r), gt(sz, 0)) {
                    if gt(byte(0, calldataload(sub(add(off, sz), 1))), 1) { r := 1 }
                }
            }

            let expOff := add(0x60, bSize)
            let modOff := add(expOff, eSize)

            // exp=0 → b^0 mod m = 1 (or 0 if m ≤ 1)
            if iszero(cdRangeNonZero(expOff, add(expOff, eSize))) {
                let out := mload(0x40)
                calldatacopy(out, calldatasize(), mSize)
                if isGt1(modOff, mSize) { mstore8(add(out, sub(mSize, 1)), 1) }
                return(out, mSize)
            }

            // base=0 or base=1: check last byte first to skip prefix scan on typical inputs
            {
                let lastByte := 0
                if gt(bSize, 0) { lastByte := byte(0, calldataload(sub(add(0x60, bSize), 1))) }
                if lt(lastByte, 2) {
                    let prefNZ := 0
                    if gt(bSize, 1) { prefNZ := cdRangeNonZero(0x60, add(0x60, sub(bSize, 1))) }
                    if iszero(prefNZ) {
                        let out := mload(0x40)
                        calldatacopy(out, calldatasize(), mSize)
                        // base=1 and m > 1: result = 1; base=0: result stays 0
                        if and(eq(lastByte, 1), isGt1(modOff, mSize)) {
                            mstore8(add(out, sub(mSize, 1)), 1)
                        }
                        return(out, mSize)
                    }
                }
            }
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
