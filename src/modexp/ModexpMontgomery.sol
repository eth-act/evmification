// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ModexpMontgomery
/// @notice Montgomery modular exponentiation.
/// @dev Solidity for control flow, assembly for the CIOS hot path.
///      May require `via_ir = true` in the compiler settings.
library ModexpMontgomery {
    /// @notice Computes base^exp mod modulus using Montgomery multiplication.
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

        result = new bytes(modLen);
        if (_isZeroBytes(modulus) || _isOneBytes(modulus)) return result;

        uint256 k = (modLen + 31) / 32; // number of 256-bit limbs

        // Convert inputs to little-endian limb arrays
        uint256[] memory n = _bytesToLimbs(modulus, k);
        uint256[] memory a = _reduceBase(base, n, k);

        // Montgomery constants
        uint256 n0inv = _computeN0inv(n[0]);
        uint256[] memory r2 = _computeR2ModN(k, n);

        // one = 1 as a k-limb number
        uint256[] memory one = new uint256[](k);
        one[0] = 1;

        // Convert to Montgomery domain: aM = a*R mod n, rM = 1*R mod n
        uint256[] memory aM = _montMul(a, r2, n, n0inv, k);
        uint256[] memory rM = _montMul(one, r2, n, n0inv, k);

        // Square-and-multiply exponentiation (left-to-right binary)
        rM = _modexpLoop(rM, aM, exponent, n, n0inv, k);

        // Convert out of Montgomery domain: result = rM * R^{-1} mod n
        uint256[] memory res = _montMul(rM, one, n, n0inv, k);

        _limbsToBytes(res, result, modLen);
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
        for (uint256 i = 0; i < len - 1; i++) {
            if (b[i] != 0) return false;
        }
        return b[len - 1] == 0x01;
    }

    // ── Limb conversion ──────────────────────────────────────────────

    /// @dev Converts big-endian bytes to a little-endian uint256[] limb array.
    ///      limbs[0] is the least significant 256-bit word.
    function _bytesToLimbs(bytes memory data, uint256 k) private pure returns (uint256[] memory limbs) {
        limbs = new uint256[](k);
        uint256 dataLen = data.length;
        uint256 fullLimbs = dataLen / 32;

        // Read full 32-byte words from the tail (least significant first)
        for (uint256 i = 0; i < fullLimbs; i++) {
            uint256 offset = dataLen - (i + 1) * 32;
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(i, 0x20)),
                    mload(add(add(data, 0x20), offset))
                )
            }
        }

        // Handle a partial most-significant limb
        uint256 rem = dataLen % 32;
        if (rem > 0) {
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

    // ── Montgomery setup ──────────────────────────────────────────────

    /// @dev Reduces base mod n via schoolbook division remainder.
    function _reduceBase(bytes memory base, uint256[] memory n, uint256 k)
        private pure returns (uint256[] memory)
    {
        uint256 baseLen = base.length;
        if (baseLen == 0) return new uint256[](k);
        uint256 baseK = (baseLen + 31) / 32;
        if (baseK < k) baseK = k;
        uint256[] memory baseLimbs = _bytesToLimbs(base, baseK);
        return _schoolbookRem(baseLimbs, baseK, n, k);
    }

    /// @dev Computes -n^{-1} mod 2^256 via Newton's method (8 doubling steps).
    function _computeN0inv(uint256 n0) private pure returns (uint256) {
        unchecked {
            uint256 inv = 1;
            for (uint256 i = 0; i < 8; i++) {
                inv *= 2 - n0 * inv;
            }
            return 0 - inv;
        }
    }

    /// @dev Computes R^2 mod n where R = 2^{256k}.
    function _computeR2ModN(uint256 k, uint256[] memory n)
        private pure returns (uint256[] memory)
    {
        uint256 dLen = 2 * k + 1;
        uint256[] memory dividend = new uint256[](dLen);
        dividend[2 * k] = 1;
        return _schoolbookRem(dividend, dLen, n, k);
    }

    // ── Division helpers ──────────────────────────────────────────────

    /// @dev 512-by-256 division: (hi:lo) / d -> (quotient, remainder).
    function _div512by256(uint256 hi, uint256 lo, uint256 d)
        private pure returns (uint256 q, uint256 rem)
    {
        assembly {
            if iszero(hi) {
                q := div(lo, d)
                rem := mod(lo, d)
            }
            if gt(hi, 0) {
                let r256 := addmod(mod(not(0), d), 1, d)
                rem := addmod(mulmod(hi, r256, d), lo, d)

                let lo_e := sub(lo, rem)
                let hi_e := sub(hi, lt(lo, rem))

                let twos := and(d, sub(0, d))
                d := div(d, twos)

                lo_e := div(lo_e, twos)
                let flip := add(div(sub(0, twos), twos), 1)
                lo_e := or(lo_e, mul(hi_e, flip))

                let inv := xor(mul(3, d), 2)
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))

                q := mul(lo_e, inv)
            }
        }
    }

    /// @dev Schoolbook long division returning remainder only (Knuth Algorithm D).
    function _schoolbookRem(
        uint256[] memory dividend, uint256 dLen,
        uint256[] memory divisor, uint256 k
    ) private pure returns (uint256[] memory remainder) {
        remainder = new uint256[](k);

        uint256 m = dLen;
        while (m > 0 && dividend[m - 1] == 0) m--;
        if (m == 0) return remainder;

        uint256 kEff = k;
        while (kEff > 1 && divisor[kEff - 1] == 0) kEff--;

        // Single-limb divisor
        if (kEff == 1) {
            uint256 d = divisor[0];
            uint256 rem = 0;
            for (uint256 i = m; i > 0;) {
                unchecked { i--; }
                (, rem) = _div512by256(rem, dividend[i], d);
            }
            remainder[0] = rem;
            return remainder;
        }

        // Dividend shorter than divisor: dividend IS the remainder
        if (m < kEff) {
            for (uint256 i = 0; i < m; i++) remainder[i] = dividend[i];
            return remainder;
        }

        uint256 numQlimbs = m - kEff + 1;

        uint256[] memory u = new uint256[](m + 1);
        assembly { mcopy(add(u, 0x20), add(dividend, 0x20), mul(m, 0x20)) }

        // Normalize: shift divisor so top limb has high bit set
        uint256 topD = divisor[kEff - 1];
        uint256 shift = 0;
        {
            uint256 tmp = topD;
            while (tmp < (1 << 255)) { tmp <<= 1; shift++; }
        }

        uint256[] memory v = new uint256[](kEff);
        if (shift > 0) {
            uint256 carry = 0;
            for (uint256 i = 0; i < kEff; i++) {
                uint256 newVal = (divisor[i] << shift) | carry;
                carry = divisor[i] >> (256 - shift);
                v[i] = newVal;
            }
            carry = 0;
            for (uint256 i = 0; i < m; i++) {
                uint256 newVal = (u[i] << shift) | carry;
                carry = u[i] >> (256 - shift);
                u[i] = newVal;
            }
            u[m] = carry;
        } else {
            assembly { mcopy(add(v, 0x20), add(divisor, 0x20), mul(kEff, 0x20)) }
        }

        uint256 vTop = v[kEff - 1];

        for (uint256 jj = numQlimbs; jj > 0;) {
            unchecked { jj--; }
            uint256 uHi = u[jj + kEff];
            uint256 uLo = u[jj + kEff - 1];

            uint256 qHat;
            {
                uint256 rHat;
                bool doRefinement;
                if (uHi >= vTop) {
                    qHat = type(uint256).max;
                    rHat = uLo + vTop;
                    doRefinement = (rHat >= uLo);
                } else {
                    (qHat, rHat) = _div512by256(uHi, uLo, vTop);
                    doRefinement = true;
                }

                if (doRefinement && kEff >= 2) {
                    uint256 vSecond = v[kEff - 2];
                    uint256 uSecond = u[jj + kEff - 2];
                    assembly {
                        let qvLo := mul(qHat, vSecond)
                        let qvMM := mulmod(qHat, vSecond, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))

                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, uSecond))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, vTop)
                            if lt(rHat, vTop) { break }
                            qvLo := mul(qHat, vSecond)
                            qvMM := mulmod(qHat, vSecond, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }
            }
            bool negative;
            assembly {
                let uP := add(u, 0x20)
                let vP := add(v, 0x20)
                let carry := 0
                let borrow := 0

                for { let i := 0 } lt(i, kEff) { i := add(i, 1) } {
                    let vi := mload(add(vP, mul(i, 0x20)))
                    let pLo := mul(qHat, vi)
                    let pMM := mulmod(qHat, vi, not(0))
                    let pH := sub(sub(pMM, pLo), lt(pMM, pLo))

                    let withCarry := add(pLo, carry)
                    let newCarry := add(pH, lt(withCarry, pLo))
                    carry := newCarry

                    let uOff := add(uP, mul(add(jj, i), 0x20))
                    let uVal := mload(uOff)
                    let diff := sub(uVal, withCarry)
                    let newBorrow := lt(uVal, withCarry)
                    let diff2 := sub(diff, borrow)
                    newBorrow := or(newBorrow, lt(diff, borrow))
                    borrow := newBorrow
                    mstore(uOff, diff2)
                }

                let uTopOff := add(uP, mul(add(jj, kEff), 0x20))
                let uTopVal := mload(uTopOff)
                let diff := sub(uTopVal, carry)
                let nb := lt(uTopVal, carry)
                let diff2 := sub(diff, borrow)
                nb := or(nb, lt(diff, borrow))
                mstore(uTopOff, diff2)
                negative := nb
            }

            if (negative) {
                assembly {
                    let uP := add(u, 0x20)
                    let vP := add(v, 0x20)
                    let carry := 0
                    for { let i := 0 } lt(i, kEff) { i := add(i, 1) } {
                        let uOff := add(uP, mul(add(jj, i), 0x20))
                        let s := add(mload(uOff), mload(add(vP, mul(i, 0x20))))
                        let c1 := lt(s, mload(uOff))
                        let s2 := add(s, carry)
                        let c2 := lt(s2, s)
                        mstore(uOff, s2)
                        carry := or(c1, c2)
                    }
                    let uTopOff := add(uP, mul(add(jj, kEff), 0x20))
                    mstore(uTopOff, add(mload(uTopOff), carry))
                }
            }
        }

        // Extract remainder from u[0..kEff-1] and denormalize (shift right)
        if (shift > 0) {
            for (uint256 i = 0; i < kEff; i++) {
                remainder[i] = u[i] >> shift;
                if (i + 1 < kEff) {
                    remainder[i] |= u[i + 1] << (256 - shift);
                }
            }
        } else {
            for (uint256 i = 0; i < kEff; i++) {
                remainder[i] = u[i];
            }
        }
    }

    // ── Square-and-multiply ───────────────────────────────────────────

    /// @dev Left-to-right binary exponentiation in the Montgomery domain.
    function _modexpLoop(
        uint256[] memory rM,
        uint256[] memory aM,
        bytes memory exponent,
        uint256[] memory n,
        uint256 n0inv,
        uint256 k
    ) private pure returns (uint256[] memory) {
        uint256 expLen = exponent.length;

        // Skip leading zero bytes
        uint256 startByte = 0;
        while (startByte < expLen && exponent[startByte] == 0) {
            startByte++;
        }
        if (startByte == expLen) return rM; // exponent is zero

        // Find the topmost set bit in the first non-zero byte
        uint8 b = uint8(exponent[startByte]);
        uint256 topBit = 7;
        while (topBit > 0 && (b >> topBit) & 1 == 0) {
            topBit--;
        }

        // Process first non-zero byte (from topBit down to bit 0)
        for (uint256 bit = topBit;;) {
            rM = _montMul(rM, rM, n, n0inv, k); // square
            if ((b >> bit) & 1 == 1) {
                rM = _montMul(rM, aM, n, n0inv, k); // multiply
            }
            if (bit == 0) break;
            unchecked { bit--; }
        }

        // Process remaining exponent bytes (all 8 bits each)
        for (uint256 byteIdx = startByte + 1; byteIdx < expLen; byteIdx++) {
            b = uint8(exponent[byteIdx]);
            for (uint256 bit = 8; bit > 0;) {
                unchecked { bit--; }
                rM = _montMul(rM, rM, n, n0inv, k); // square
                if ((b >> bit) & 1 == 1) {
                    rM = _montMul(rM, aM, n, n0inv, k); // multiply
                }
            }
        }

        return rM;
    }

    // ── Montgomery multiplication (CIOS) ──────────────────────────────

    /// @dev Computes a * b * R^{-1} mod n using CIOS (Coarsely Integrated Operand Scanning).
    ///      This is the only assembly-heavy function — the innermost hot loop.
    function _montMul(
        uint256[] memory a,
        uint256[] memory b,
        uint256[] memory n,
        uint256 n0inv,
        uint256 k
    ) private pure returns (uint256[] memory res) {
        res = new uint256[](k);

        assembly {
            let aP := add(a, 0x20) // skip length word to reach data
            let bP := add(b, 0x20)
            let nP := add(n, 0x20)
            let resP := add(res, 0x20)

            // Allocate scratch t[0..k+1]
            let tP := mload(0x40)
            mstore(0x40, add(tP, mul(add(k, 2), 0x20)))

            // Zero t
            for { let i := 0 } lt(i, add(k, 2)) { i := add(i, 1) } {
                mstore(add(tP, mul(i, 0x20)), 0)
            }

            // Main CIOS loop: one iteration per limb of a
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let ai := mload(add(aP, mul(i, 0x20)))

                // Step 1: Multiply pass — t += a[i] * b
                {
                    let carry := 0
                    for { let j := 0 } lt(j, k) { j := add(j, 1) } {
                        let tOff := add(tP, mul(j, 0x20))
                        let bj := mload(add(bP, mul(j, 0x20)))

                        // Full 512-bit product: (hi, lo) = ai * bj
                        let lo := mul(ai, bj)
                        let mmr := mulmod(ai, bj, not(0))
                        let hi := sub(sub(mmr, lo), lt(mmr, lo))

                        // Accumulate: sum = lo + t[j] + carry
                        let s1 := add(lo, mload(tOff))
                        let c1 := lt(s1, lo)
                        let s2 := add(s1, carry)
                        mstore(tOff, s2)
                        carry := add(hi, add(c1, lt(s2, s1)))
                    }

                    // Propagate carry into t[k] and t[k+1]
                    let tkOff := add(tP, mul(k, 0x20))
                    let tk := mload(tkOff)
                    let tkNew := add(tk, carry)
                    mstore(tkOff, tkNew)
                    mstore(
                        add(tP, mul(add(k, 1), 0x20)),
                        add(mload(add(tP, mul(add(k, 1), 0x20))), lt(tkNew, tk))
                    )
                }

                // Step 2: Reduce pass — m = t[0]*n0inv; t += m*n; shift right one word
                {
                    let m := mul(mload(tP), n0inv)
                    let carry := 0

                    for { let j := 0 } lt(j, k) { j := add(j, 1) } {
                        let tOff := add(tP, mul(j, 0x20))
                        let nj := mload(add(nP, mul(j, 0x20)))

                        let lo := mul(m, nj)
                        let mmr := mulmod(m, nj, not(0))
                        let hi := sub(sub(mmr, lo), lt(mmr, lo))

                        let s1 := add(lo, mload(tOff))
                        let c1 := lt(s1, lo)
                        let s2 := add(s1, carry)
                        let c2 := lt(s2, s1)

                        // Shift down: write result to t[j-1] (division by 2^256)
                        if gt(j, 0) { mstore(add(tP, mul(sub(j, 1), 0x20)), s2) }

                        carry := add(hi, add(c1, c2))
                    }

                    // Propagate carry into upper limbs (with shift)
                    let tkVal := mload(add(tP, mul(k, 0x20)))
                    let sum := add(tkVal, carry)
                    mstore(add(tP, mul(sub(k, 1), 0x20)), sum)
                    let tk1Off := add(tP, mul(add(k, 1), 0x20))
                    mstore(add(tP, mul(k, 0x20)), add(mload(tk1Off), lt(sum, tkVal)))
                    mstore(tk1Off, 0)
                }
            }

            // Final conditional subtraction: if t >= n then t -= n
            {
                let doSub := gt(mload(add(tP, mul(k, 0x20))), 0)

                if iszero(doSub) {
                    // Compare t vs n from the most significant limb downward
                    doSub := 1 // assume t >= n (covers the equal case)
                    for { let i := k } gt(i, 0) {} {
                        i := sub(i, 1)
                        let tL := mload(add(tP, mul(i, 0x20)))
                        let nL := mload(add(nP, mul(i, 0x20)))
                        if gt(tL, nL) { i := 0 }             // t > n, subtract
                        if lt(tL, nL) { doSub := 0 i := 0 }  // t < n, no subtract
                        // if equal, continue to next limb
                    }
                }

                // Copy t[0..k-1] to res
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                    mstore(add(resP, mul(i, 0x20)), mload(add(tP, mul(i, 0x20))))
                }

                // Conditionally subtract n
                if doSub {
                    let borrow := 0
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        let off := add(resP, mul(i, 0x20))
                        let rL := mload(off)
                        let nL := mload(add(nP, mul(i, 0x20)))
                        let d := sub(rL, nL)
                        let nb := lt(rL, nL)
                        let d2 := sub(d, borrow)
                        borrow := or(nb, lt(d, borrow))
                        mstore(off, d2)
                    }
                }
            }
        }
    }
}
