// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title LimbMath
/// @notice Shared big-integer helpers for modular exponentiation.
/// @dev All numbers are little-endian uint256[] limb arrays (limbs[0] = least significant).
library LimbMath {
    // ── Byte-level helpers ────────────────────────────────────────────

    function isZeroBytes(bytes memory b) internal pure returns (bool z) {
        assembly {
            let len := mload(b)
            let ptr := add(b, 0x20)
            let end := add(ptr, len)
            z := 1
            for {} lt(ptr, end) { ptr := add(ptr, 0x20) } {
                let w := mload(ptr)
                let rem := sub(end, ptr)
                if lt(rem, 0x20) { w := shr(mul(sub(0x20, rem), 8), w) }
                if w { z := 0 ptr := end }
            }
        }
    }

    function isOneBytes(bytes memory b) internal pure returns (bool z) {
        if (b.length == 0) return false;
        assembly {
            let len := mload(b)
            let ptr := add(b, 0x20)
            let prefixLen := sub(len, 1)
            let end := add(ptr, prefixLen)
            z := 1
            for {} lt(ptr, end) { ptr := add(ptr, 0x20) } {
                let w := mload(ptr)
                let rem := sub(end, ptr)
                if lt(rem, 0x20) { w := shr(mul(sub(0x20, rem), 8), w) }
                if w { z := 0 ptr := end }
            }
            if z { z := eq(byte(0, mload(add(add(b, 0x20), prefixLen))), 0x01) }
        }
    }

    // ── Limb conversion ──────────────────────────────────────────────

    function bytesToLimbs(bytes memory data, uint256 k) internal pure returns (uint256[] memory limbs) {
        limbs = new uint256[](k);
        uint256 dataLen = data.length;
        uint256 fullLimbs = dataLen / 32;

        for (uint256 i = 0; i < fullLimbs; i++) {
            uint256 offset = dataLen - (i + 1) * 32;
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(i, 0x20)),
                    mload(add(add(data, 0x20), offset))
                )
            }
        }

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

    function limbsToBytes(uint256[] memory limbs, bytes memory out, uint256 dataLen) internal pure {
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

    function copyLimbs(uint256[] memory src, uint256[] memory dst, uint256 len) internal pure {
        assembly {
            mcopy(add(dst, 0x20), add(src, 0x20), mul(len, 0x20))
        }
    }

    // ── Division helpers ──────────────────────────────────────────────

    /// @dev 512-by-256 division: (hi:lo) / d -> (quotient, remainder).
    ///      Requires hi < d (quotient fits in 256 bits).
    function div512by256(uint256 hi, uint256 lo, uint256 d)
        internal pure returns (uint256 q, uint256 rem)
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

    // ── Schoolbook division (Knuth Algorithm D) ───────────────────────

    /// @dev Schoolbook long division: dividend[0..dLen-1] / divisor[0..k-1].
    ///      Returns (quotient, remainder). All arrays are little-endian limbs.
    function schoolbookDiv(
        uint256[] memory dividend,
        uint256 dLen,
        uint256[] memory divisor,
        uint256 k
    ) internal pure returns (uint256[] memory quotient, uint256[] memory rem) {
        rem = new uint256[](k);

        uint256 m = dLen;
        while (m > 0 && dividend[m - 1] == 0) {
            m--;
        }
        if (m == 0) {
            quotient = new uint256[](1);
            return (quotient, rem);
        }

        uint256 kEff = k;
        while (kEff > 1 && divisor[kEff - 1] == 0) {
            kEff--;
        }

        // Single-limb divisor
        if (kEff == 1) {
            uint256 d = divisor[0];
            quotient = new uint256[](m);
            uint256 remainder = 0;
            for (uint256 i = m; i > 0;) {
                unchecked { i--; }
                uint256 q;
                (q, remainder) = div512by256(remainder, dividend[i], d);
                quotient[i] = q;
            }
            rem[0] = remainder;
            return (quotient, rem);
        }

        // Dividend shorter than divisor
        if (m < kEff) {
            quotient = new uint256[](1);
            for (uint256 i = 0; i < m; i++) rem[i] = dividend[i];
            return (quotient, rem);
        }

        uint256 numQlimbs = m - kEff + 1;
        quotient = new uint256[](numQlimbs);

        uint256[] memory u = new uint256[](m + 1);
        assembly {
            mcopy(add(u, 0x20), add(dividend, 0x20), mul(m, 0x20))
        }

        // Normalize: shift divisor so top limb has high bit set (binary search for shift)
        uint256 topD = divisor[kEff - 1];
        uint256 shift = _clz(topD);

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
            assembly {
                mcopy(add(v, 0x20), add(divisor, 0x20), mul(kEff, 0x20))
            }
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
                    (qHat, rHat) = div512by256(uHi, uLo, vTop);
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
                qHat--;
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

            quotient[jj] = qHat;
        }

        // Extract remainder from u[0..kEff-1] and denormalize
        if (shift > 0) {
            for (uint256 i = 0; i < kEff; i++) {
                rem[i] = u[i] >> shift;
                if (i + 1 < kEff) {
                    rem[i] |= u[i + 1] << (256 - shift);
                }
            }
        } else {
            for (uint256 i = 0; i < kEff; i++) {
                rem[i] = u[i];
            }
        }
    }

    /// @dev Schoolbook division returning remainder only.
    function schoolbookRem(
        uint256[] memory dividend,
        uint256 dLen,
        uint256[] memory divisor,
        uint256 k
    ) internal pure returns (uint256[] memory rem) {
        (, rem) = schoolbookDiv(dividend, dLen, divisor, k);
    }

    /// @dev Reduces base mod n via schoolbook division remainder.
    function reduceBase(bytes memory base, uint256[] memory n, uint256 k)
        internal pure returns (uint256[] memory)
    {
        uint256 baseLen = base.length;
        if (baseLen == 0) return new uint256[](k);
        uint256 baseK = (baseLen + 31) / 32;
        if (baseK < k) baseK = k;
        uint256[] memory baseLimbs = bytesToLimbs(base, baseK);
        return schoolbookRem(baseLimbs, baseK, n, k);
    }

    // ── Multiplication ──────────────────────────────────────────────

    /// @dev Schoolbook multiplication: result = a[0..aLen-1] * b[0..bLen-1].
    ///      Result is (aLen + bLen) limbs.
    function schoolbookMul(
        uint256[] memory a,
        uint256 aLen,
        uint256[] memory b,
        uint256 bLen
    ) internal pure returns (uint256[] memory result) {
        uint256 rLen = aLen + bLen;
        result = new uint256[](rLen);

        assembly {
            let aP := add(a, 0x20)
            let bP := add(b, 0x20)
            let resP := add(result, 0x20)

            for { let i := 0 } lt(i, aLen) { i := add(i, 1) } {
                let ai := mload(add(aP, mul(i, 0x20)))
                if gt(ai, 0) {
                    let carry := 0
                    for { let j := 0 } lt(j, bLen) { j := add(j, 1) } {
                        let rOff := add(resP, mul(add(i, j), 0x20))
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
                    let rOff := add(resP, mul(add(i, bLen), 0x20))
                    mstore(rOff, add(mload(rOff), carry))
                }
            }
        }
    }

    // ── Private helpers ───────────────────────────────────────────────

    /// @dev Count leading zeros of a nonzero uint256 using binary search (8 steps vs 255 worst case).
    function _clz(uint256 x) private pure returns (uint256 n) {
        n = 0;
        if (x < (1 << 128)) { x <<= 128; n += 128; }
        if (x < (1 << 192)) { x <<= 64; n += 64; }
        if (x < (1 << 224)) { x <<= 32; n += 32; }
        if (x < (1 << 240)) { x <<= 16; n += 16; }
        if (x < (1 << 248)) { x <<= 8; n += 8; }
        if (x < (1 << 252)) { x <<= 4; n += 4; }
        if (x < (1 << 254)) { x <<= 2; n += 2; }
        if (x < (1 << 255)) { n += 1; }
    }
}
