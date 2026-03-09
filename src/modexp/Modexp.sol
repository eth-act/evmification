// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ModexpMontgomery} from "./ModexpMontgomery.sol";
import {ModexpPow2} from "./ModexpPow2.sol";

/// @title Modexp
/// @notice Modular exponentiation for any modulus.
/// @dev Uses Montgomery multiplication for odd moduli and CRT decomposition
///      (Montgomery + Pow2) for even moduli.
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
        uint256 modLen = modulus.length;
        if (modLen == 0) return new bytes(0);

        // Check if modulus is odd (last byte has bit 0 set)
        if (uint8(modulus[modLen - 1]) & 1 == 1) {
            return ModexpMontgomery.modexp(base, exponent, modulus);
        }

        // Even modulus: check for all-zero modulus before doing work
        if (_isZeroBytes(modulus)) {
            return new bytes(modLen);
        }

        // CRT decomposition: factor modulus = mOdd * 2^kBits
        uint256 kBits = _countTrailingZeroBits(modulus);
        bytes memory mOdd = _rightShiftBytes(modulus, kBits);

        // Pure power of 2: mOdd == 1
        if (_isOneBytes(mOdd)) {
            bytes memory pow2Result = ModexpPow2.modexp(base, exponent, kBits);
            result = new bytes(modLen);
            uint256 pow2Len = pow2Result.length;
            uint256 offset = modLen - pow2Len;
            assembly {
                mcopy(add(add(result, 0x20), offset), add(pow2Result, 0x20), pow2Len)
            }
            return result;
        }

        // Compute r1 = base^exp mod mOdd (via Montgomery)
        bytes memory r1 = ModexpMontgomery.modexp(base, exponent, mOdd);

        // Compute r2 = base^exp mod 2^kBits (via Pow2)
        bytes memory r2 = ModexpPow2.modexp(base, exponent, kBits);

        // CRT combine
        result = _crtCombine(r1, r2, mOdd, kBits, modLen);
    }

    // ── Byte-level helpers ────────────────────────────────────────────

    /// @dev Returns true if all bytes are zero.
    function _isZeroBytes(bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] != 0) return false;
        }
        return true;
    }

    /// @dev Returns true if the value is exactly 1 (big-endian).
    function _isOneBytes(bytes memory b) private pure returns (bool) {
        uint256 len = b.length;
        if (len == 0) return false;
        for (uint256 i = 0; i < len - 1; i++) {
            if (b[i] != 0) return false;
        }
        return b[len - 1] == 0x01;
    }

    /// @dev Count trailing zero bits in big-endian modulus.
    ///      Walks from the last byte (LSB) backwards.
    function _countTrailingZeroBits(bytes memory modulus) private pure returns (uint256 count) {
        uint256 len = modulus.length;
        count = 0;
        // Walk from last byte (least significant) backwards
        for (uint256 i = len; i > 0;) {
            unchecked { i--; }
            uint8 b = uint8(modulus[i]);
            if (b == 0) {
                count += 8;
            } else {
                // Count trailing zeros in this byte
                if (b & 1 != 0) return count;
                if (b & 2 != 0) return count + 1;
                if (b & 4 != 0) return count + 2;
                if (b & 8 != 0) return count + 3;
                if (b & 16 != 0) return count + 4;
                if (b & 32 != 0) return count + 5;
                if (b & 64 != 0) return count + 6;
                return count + 7; // must be bit 7
            }
        }
    }

    /// @dev Right-shift big-endian bytes by `shift` bits. Returns minimal-length result.
    function _rightShiftBytes(bytes memory data, uint256 shift) private pure returns (bytes memory) {
        uint256 dataLen = data.length;
        uint256 byteShift = shift / 8;
        uint256 bitShift = shift % 8;

        // After removing byteShift trailing bytes, we have dataLen - byteShift bytes
        if (byteShift >= dataLen) return new bytes(1); // would be zero

        uint256 srcLen = dataLen - byteShift;

        // Create temp buffer for shifted result
        bytes memory tmp = new bytes(srcLen);

        if (bitShift == 0) {
            // Just copy the leading srcLen bytes
            assembly {
                mcopy(add(tmp, 0x20), add(data, 0x20), srcLen)
            }
        } else {
            // Shift bits: in big-endian, right-shift means each byte gets
            // high bits from itself >> bitShift, low bits from previous byte << (8-bitShift)
            for (uint256 i = 0; i < srcLen; i++) {
                uint256 cur = uint256(uint8(data[i]));
                uint256 shifted = cur >> bitShift;
                if (i > 0) {
                    uint256 prev = uint256(uint8(data[i - 1]));
                    shifted |= (prev << (8 - bitShift)) & 0xFF;
                }
                tmp[i] = bytes1(uint8(shifted));
            }
        }

        // Strip leading zero bytes
        uint256 start = 0;
        while (start < srcLen - 1 && uint8(tmp[start]) == 0) {
            start++;
        }

        uint256 resultLen = srcLen - start;
        bytes memory result = new bytes(resultLen);
        assembly {
            mcopy(add(result, 0x20), add(add(tmp, 0x20), start), resultLen)
        }
        return result;
    }

    // ── Limb conversion ──────────────────────────────────────────────

    /// @dev Converts big-endian bytes to a little-endian uint256[] limb array.
    function _bytesToLimbs(bytes memory data, uint256 k) private pure returns (uint256[] memory limbs) {
        limbs = new uint256[](k);
        uint256 dataLen = data.length;
        uint256 fullLimbs = dataLen / 32;

        for (uint256 i = 0; i < fullLimbs; i++) {
            if (i >= k) break;
            uint256 offset = dataLen - (i + 1) * 32;
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(i, 0x20)),
                    mload(add(add(data, 0x20), offset))
                )
            }
        }

        uint256 rem = dataLen % 32;
        if (rem > 0 && fullLimbs < k) {
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(fullLimbs, 0x20)),
                    shr(mul(sub(32, rem), 8), mload(add(data, 0x20)))
                )
            }
        }
    }

    /// @dev Converts a little-endian uint256[] limb array to big-endian bytes.
    function _limbsToBytes(uint256[] memory limbs, bytes memory out, uint256 dataLen) private pure {
        uint256 fullLimbs = dataLen / 32;

        for (uint256 i = 0; i < fullLimbs; i++) {
            uint256 offset = dataLen - (i + 1) * 32;
            uint256 val = limbs[i];
            assembly {
                mstore(add(add(out, 0x20), offset), val)
            }
        }

        uint256 rem = dataLen % 32;
        if (rem > 0) {
            assembly {
                let val := mload(add(add(limbs, 0x20), mul(fullLimbs, 0x20)))
                let shift := mul(sub(32, rem), 8)
                let shifted := shl(shift, val)
                let ptr := add(out, 0x20)
                let existing := mload(ptr)
                let mask := not(sub(shl(shift, 1), 1))
                mstore(ptr, or(and(shifted, mask), and(existing, not(mask))))
            }
        }
    }

    // ── Limb arithmetic helpers ──────────────────────────────────────

    /// @dev Truncate limbs to kBits: mask the top limb.
    function _truncateLimbs(uint256[] memory limbs, uint256 kBits, uint256 kLimbs) private pure {
        if (kLimbs == 0) return;
        uint256 topBits = kBits % 256;
        if (topBits != 0) {
            uint256 mask = (1 << topBits) - 1;
            limbs[kLimbs - 1] &= mask;
        }
    }

    /// @dev Two's complement negation of limbs (negate mod 2^(256*len)).
    function _negateLimbs(uint256[] memory a, uint256 len) private pure returns (uint256[] memory result) {
        result = new uint256[](len);
        assembly {
            let aP := add(a, 0x20)
            let rP := add(result, 0x20)
            let carry := 1
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                let ai := mload(add(aP, mul(i, 0x20)))
                let notAi := not(ai)
                let s := add(notAi, carry)
                carry := lt(s, notAi)
                mstore(add(rP, mul(i, 0x20)), s)
            }
        }
    }

    /// @dev Schoolbook multiply keeping only the bottom kLimbs limbs.
    function _lowMul(
        uint256[] memory a,
        uint256[] memory b,
        uint256 aLen,
        uint256 bLen,
        uint256 kLimbs
    ) private pure returns (uint256[] memory res) {
        res = new uint256[](kLimbs);
        assembly {
            let resBase := add(res, 0x20)
            let aBase := add(a, 0x20)
            let bBase := add(b, 0x20)

            for { let i := 0 } lt(i, aLen) { i := add(i, 1) } {
                if iszero(lt(i, kLimbs)) { break }
                let ai := mload(add(aBase, mul(i, 0x20)))
                if iszero(ai) { continue }

                let carry := 0
                let jLimit := sub(kLimbs, i)
                if gt(jLimit, bLen) { jLimit := bLen }

                for { let j := 0 } lt(j, jLimit) { j := add(j, 1) } {
                    let bj := mload(add(bBase, mul(j, 0x20)))
                    let pos := add(i, j)
                    let resPtr := add(resBase, mul(pos, 0x20))

                    let lo := mul(ai, bj)
                    let mm := mulmod(ai, bj, not(0))
                    let hi := sub(sub(mm, lo), lt(mm, lo))

                    let existing := mload(resPtr)
                    let s1 := add(existing, lo)
                    let c1 := lt(s1, existing)
                    let s2 := add(s1, carry)
                    let c2 := lt(s2, s1)

                    mstore(resPtr, s2)
                    carry := add(hi, add(c1, c2))
                }
                // carry above kLimbs is discarded
            }
        }
    }

    /// @dev Full schoolbook multiply, result truncated to outLimbs.
    function _fullMul(
        uint256[] memory a,
        uint256 aLen,
        uint256[] memory b,
        uint256 bLen,
        uint256 outLimbs
    ) private pure returns (uint256[] memory result) {
        result = new uint256[](outLimbs);
        assembly {
            let aP := add(a, 0x20)
            let bP := add(b, 0x20)
            let resP := add(result, 0x20)

            for { let i := 0 } lt(i, aLen) { i := add(i, 1) } {
                let ai := mload(add(aP, mul(i, 0x20)))
                if iszero(ai) { continue }

                let carry := 0
                for { let j := 0 } lt(j, bLen) { j := add(j, 1) } {
                    let pos := add(i, j)
                    if iszero(lt(pos, outLimbs)) { break }
                    let rOff := add(resP, mul(pos, 0x20))
                    let bj := mload(add(bP, mul(j, 0x20)))

                    let lo := mul(ai, bj)
                    let mmr := mulmod(ai, bj, not(0))
                    let hi := sub(sub(mmr, lo), lt(mmr, lo))

                    let s1 := add(lo, mload(rOff))
                    let c1 := lt(s1, lo)
                    let s2 := add(s1, carry)
                    mstore(rOff, s2)
                    carry := add(hi, add(c1, lt(s2, s1)))
                }
                // Propagate final carry through remaining limbs
                for { let ci := add(i, bLen) } and(lt(ci, outLimbs), gt(carry, 0)) { ci := add(ci, 1) } {
                    let rOff := add(resP, mul(ci, 0x20))
                    let old := mload(rOff)
                    let newVal := add(old, carry)
                    mstore(rOff, newVal)
                    carry := lt(newVal, old)
                }
            }
        }
    }

    /// @dev Add two limb arrays: result = a + b, returns outLimbs limbs (no overflow handling beyond outLimbs).
    function _addLimbs(
        uint256[] memory a,
        uint256 aLen,
        uint256[] memory b,
        uint256 bLen,
        uint256 outLimbs
    ) private pure returns (uint256[] memory result) {
        result = new uint256[](outLimbs);
        assembly {
            let aP := add(a, 0x20)
            let bP := add(b, 0x20)
            let rP := add(result, 0x20)
            let carry := 0

            for { let i := 0 } lt(i, outLimbs) { i := add(i, 1) } {
                let ai := 0
                if lt(i, aLen) { ai := mload(add(aP, mul(i, 0x20))) }
                let bi := 0
                if lt(i, bLen) { bi := mload(add(bP, mul(i, 0x20))) }

                let s := add(ai, bi)
                let c1 := lt(s, ai)
                let s2 := add(s, carry)
                let c2 := lt(s2, s)
                mstore(add(rP, mul(i, 0x20)), s2)
                carry := or(c1, c2)
            }
        }
    }

    /// @dev Subtract limb arrays: result = a - b (mod 2^(256*outLimbs)).
    function _subLimbs(
        uint256[] memory a,
        uint256 aLen,
        uint256[] memory b,
        uint256 bLen,
        uint256 outLimbs
    ) private pure returns (uint256[] memory result) {
        result = new uint256[](outLimbs);
        assembly {
            let aP := add(a, 0x20)
            let bP := add(b, 0x20)
            let rP := add(result, 0x20)
            let borrow := 0

            for { let i := 0 } lt(i, outLimbs) { i := add(i, 1) } {
                let ai := 0
                if lt(i, aLen) { ai := mload(add(aP, mul(i, 0x20))) }
                let bi := 0
                if lt(i, bLen) { bi := mload(add(bP, mul(i, 0x20))) }

                let d := sub(ai, bi)
                let nb := lt(ai, bi)
                let d2 := sub(d, borrow)
                nb := or(nb, lt(d, borrow))
                borrow := nb
                mstore(add(rP, mul(i, 0x20)), d2)
            }
        }
    }

    // ── Newton iteration for modular inverse mod 2^k ─────────────────

    /// @dev Computes mOdd^(-1) mod 2^kBits via Newton iteration.
    ///      mOdd must be odd. Start with inv=1, iterate inv = inv*(2 - mOdd*inv) mod 2^precision,
    ///      doubling precision each step.
    function _computeModInvPow2(
        uint256[] memory mOddLimbs,
        uint256 mOddLen,
        uint256 kBits,
        uint256 kLimbs
    ) private pure returns (uint256[] memory inv) {
        // Start: inv = 1 (1 limb), precision = 1 bit
        inv = new uint256[](kLimbs);
        inv[0] = 1;

        // Newton iteration: inv = inv * (2 - mOdd * inv) mod 2^precision
        // Each step doubles the number of correct bits.
        // We need ceil(log2(kBits)) iterations.
        // Save free memory pointer; temporaries are reclaimed each iteration.
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }

        uint256 precision = 1;
        while (precision < kBits) {
            precision *= 2;
            if (precision > kBits) precision = kBits;

            uint256 precLimbs = (precision + 255) / 256;

            assembly { mstore(0x40, freeMemBase) }

            // product = mOdd * inv mod 2^precision (low multiply)
            uint256[] memory product = _lowMul(mOddLimbs, inv, mOddLen, kLimbs, precLimbs);
            _truncateLimbs(product, precision, precLimbs);

            // twoMinusProduct = negate(product) + 2, all mod 2^precision
            uint256[] memory neg = _negateLimbs(product, precLimbs);
            // Add 2 with carry propagation
            {
                uint256 carry;
                assembly {
                    let ptr := add(neg, 0x20)
                    let old := mload(ptr)
                    let newVal := add(old, 2)
                    mstore(ptr, newVal)
                    carry := lt(newVal, old)
                }
                for (uint256 ci = 1; ci < precLimbs && carry > 0; ci++) {
                    assembly {
                        let ptr := add(add(neg, 0x20), mul(ci, 0x20))
                        let old := mload(ptr)
                        let newVal := add(old, carry)
                        mstore(ptr, newVal)
                        carry := lt(newVal, old)
                    }
                }
            }
            _truncateLimbs(neg, precision, precLimbs);

            // newInv = inv * neg mod 2^precision
            uint256[] memory newInv = _lowMul(inv, neg, kLimbs, precLimbs, precLimbs);
            _truncateLimbs(newInv, precision, precLimbs);

            // Copy newInv back into inv (expanding to kLimbs)
            assembly {
                mcopy(add(inv, 0x20), add(newInv, 0x20), mul(precLimbs, 0x20))
            }
            // Zero out remaining limbs
            for (uint256 i = precLimbs; i < kLimbs; i++) {
                inv[i] = 0;
            }
        }

        _truncateLimbs(inv, kBits, kLimbs);
    }

    // ── CRT combine ─────────────────────────────────────────────────

    /// @dev CRT combine: result = r1 + mOdd * (((r2 - r1) * mOddInv) mod 2^k)
    function _crtCombine(
        bytes memory r1,
        bytes memory r2,
        bytes memory mOdd,
        uint256 kBits,
        uint256 modLen
    ) private pure returns (bytes memory result) {
        uint256 kLimbs = (kBits + 255) / 256;
        uint256 totalLimbs = (modLen + 31) / 32;
        uint256 mOddLimbCount = (mOdd.length + 31) / 32;

        // Convert to limbs
        uint256[] memory r1Limbs = _bytesToLimbs(r1, totalLimbs);
        uint256[] memory r2Limbs = _bytesToLimbs(r2, kLimbs);
        uint256[] memory mOddLimbs = _bytesToLimbs(mOdd, mOddLimbCount);

        // Compute mOddInv = mOdd^(-1) mod 2^kBits
        uint256[] memory mOddInv = _computeModInvPow2(mOddLimbs, mOddLimbCount, kBits, kLimbs);

        // diff = (r2 - r1) mod 2^kBits
        // _subLimbs reads at most kLimbs from each input, so r1Limbs (totalLimbs) is safe
        uint256 r1SubLen = totalLimbs < kLimbs ? totalLimbs : kLimbs;
        uint256[] memory diff = _subLimbs(r2Limbs, kLimbs, r1Limbs, r1SubLen, kLimbs);
        _truncateLimbs(diff, kBits, kLimbs);

        // x = (diff * mOddInv) mod 2^kBits
        uint256[] memory x = _lowMul(diff, mOddInv, kLimbs, kLimbs, kLimbs);
        _truncateLimbs(x, kBits, kLimbs);

        // product = mOdd * x (full multiply, fits in totalLimbs)
        uint256[] memory product = _fullMul(mOddLimbs, mOddLimbCount, x, kLimbs, totalLimbs);

        // result = r1 + product
        uint256[] memory resLimbs = _addLimbs(r1Limbs, totalLimbs, product, totalLimbs, totalLimbs);

        // Convert back to bytes
        result = new bytes(modLen);
        _limbsToBytes(resLimbs, result, modLen);
    }
}
