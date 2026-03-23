// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LimbMath} from "../modexp/LimbMath.sol";

/// @title Fp
/// @notice BLS12-381 base field (Fp) arithmetic library.
/// @dev All field elements are 48-byte big-endian `bytes memory`.
///      Field modulus p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
library Fp {
    // ── Field constants ──────────────────────────────────────────────

    /// @dev Base field modulus p (48 bytes, big-endian).
    bytes constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev p - 2, used for Fermat inversion: a^(p-2) = a^{-1} mod p.
    bytes constant P_MINUS_2 =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa9";

    /// @dev (p + 1) / 4, used for square root since p = 3 mod 4.
    bytes constant P_PLUS_1_DIV_4 =
        hex"0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab";

    /// @dev (p - 3) / 4, used in sqrtRatio (RFC 9380 c1 constant).
    bytes constant P_MINUS_3_DIV_4 =
        hex"0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaaa";

    /// @dev p as a 2-limb little-endian array, cached for mul/sqr.
    ///      limbs[0] = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    ///      limbs[1] = 0x1a0111ea397fe69a4b1ba7b6434bacd7

    // ── Arithmetic operations ────────────────────────────────────────

    /// @notice (a + b) mod p.
    /// @dev Uses conditional subtraction instead of modexp for reduction.
    function add(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // Load a as (aHi:aLo) — 128-bit hi, 256-bit lo
            let aLen := mload(a)
            let aLo := 0
            let aHi := 0
            if gt(aLen, 31) {
                aLo := mload(add(a, add(0x20, sub(aLen, 32))))
                let hiBytes := sub(aLen, 32)
                if gt(hiBytes, 0) {
                    aHi := shr(mul(sub(32, hiBytes), 8), mload(add(a, 0x20)))
                }
            }
            if and(gt(aLen, 0), lt(aLen, 32)) {
                aLo := shr(mul(sub(32, aLen), 8), mload(add(a, 0x20)))
            }
            if eq(aLen, 32) { aLo := mload(add(a, 0x20)) }

            // Load b as (bHi:bLo)
            let bLen := mload(b)
            let bLo := 0
            let bHi := 0
            if gt(bLen, 31) {
                bLo := mload(add(b, add(0x20, sub(bLen, 32))))
                let hiBytes := sub(bLen, 32)
                if gt(hiBytes, 0) {
                    bHi := shr(mul(sub(32, hiBytes), 8), mload(add(b, 0x20)))
                }
            }
            if and(gt(bLen, 0), lt(bLen, 32)) {
                bLo := shr(mul(sub(32, bLen), 8), mload(add(b, 0x20)))
            }
            if eq(bLen, 32) { bLo := mload(add(b, 0x20)) }

            // sum = a + b (with carry into hi)
            let sLo := add(aLo, bLo)
            let carry := lt(sLo, aLo)
            let sHi := add(add(aHi, bHi), carry)

            // Conditional subtract p if sum >= p
            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // Check if (sHi:sLo) >= (pHi:pLo)
            let gte := or(gt(sHi, pHi), and(eq(sHi, pHi), iszero(lt(sLo, pLo))))
            if gte {
                let newLo := sub(sLo, pLo)
                let borrow := gt(pLo, sLo)
                sHi := sub(sHi, add(pHi, borrow))
                sLo := newLo
            }

            mstore(add(result, 0x20), shl(128, sHi))
            mstore(add(result, 0x30), sLo)
        }
    }

    /// @notice (a - b) mod p.
    /// @dev Direct subtraction with conditional add of p.
    function sub(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // Load a as (aHi:aLo)
            let aLen := mload(a)
            let aLo := 0
            let aHi := 0
            if gt(aLen, 31) {
                aLo := mload(add(a, add(0x20, sub(aLen, 32))))
                let hiBytes := sub(aLen, 32)
                if gt(hiBytes, 0) {
                    aHi := shr(mul(sub(32, hiBytes), 8), mload(add(a, 0x20)))
                }
            }
            if and(gt(aLen, 0), lt(aLen, 32)) {
                aLo := shr(mul(sub(32, aLen), 8), mload(add(a, 0x20)))
            }
            if eq(aLen, 32) { aLo := mload(add(a, 0x20)) }

            // Load b as (bHi:bLo)
            let bLen := mload(b)
            let bLo := 0
            let bHi := 0
            if gt(bLen, 31) {
                bLo := mload(add(b, add(0x20, sub(bLen, 32))))
                let hiBytes := sub(bLen, 32)
                if gt(hiBytes, 0) {
                    bHi := shr(mul(sub(32, hiBytes), 8), mload(add(b, 0x20)))
                }
            }
            if and(gt(bLen, 0), lt(bLen, 32)) {
                bLo := shr(mul(sub(32, bLen), 8), mload(add(b, 0x20)))
            }
            if eq(bLen, 32) { bLo := mload(add(b, 0x20)) }

            // diff = a - b (with borrow)
            let dLo := sub(aLo, bLo)
            let borrow := gt(bLo, aLo)
            let dHi := sub(sub(aHi, bHi), borrow)

            // If underflow (a < b), add p
            let underflow := or(gt(bHi, aHi), and(eq(aHi, bHi), gt(bLo, aLo)))
            // Also underflow if bHi == aHi and bLo == aLo but borrow from prior...
            // Actually just check if dHi has wrapped (top bits set for 128-bit value)
            // Since both a,b < p < 2^381, the hi parts are < 2^128.
            // If we underflowed, dHi will have wrapped to a huge value (> 2^128).
            underflow := gt(dHi, 0x1a0111ea397fe69a4b1ba7b6434bacd7)

            if underflow {
                let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                let newLo := add(dLo, pLo)
                let c := lt(newLo, dLo)
                dHi := add(add(dHi, pHi), c)
                dLo := newLo
            }

            mstore(add(result, 0x20), shl(128, dHi))
            mstore(add(result, 0x30), dLo)
        }
    }

    /// @notice -a mod p, computed as p - a.
    function neg(bytes memory a) internal pure returns (bytes memory result) {
        if (LimbMath.isZeroBytes(a)) {
            result = new bytes(48);
            return result;
        }
        result = new bytes(48);
        assembly {
            // p as (pHi: 128 bits, pLo: 256 bits) big-endian
            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // Load a as (aHi, aLo). Handle variable-length input.
            let aLen := mload(a)
            let aLo := 0
            let aHi := 0

            switch gt(aLen, 31)
            case 1 {
                // aLo = last 32 bytes
                aLo := mload(add(a, add(0x20, sub(aLen, 32))))
                // aHi = remaining upper bytes (up to 16 bytes), right-aligned to 128 bits
                let hiBytes := sub(aLen, 32)
                if gt(hiBytes, 0) {
                    // Load 32 bytes starting at data start, shift right to align
                    let raw := mload(add(a, 0x20))
                    aHi := shr(mul(sub(32, hiBytes), 8), raw)
                }
            }
            default {
                // Entire value fits in 32 bytes
                if gt(aLen, 0) {
                    let raw := mload(add(a, 0x20))
                    aLo := shr(mul(sub(32, aLen), 8), raw)
                }
            }

            // Subtract: (pHi:pLo) - (aHi:aLo)
            let rLo := sub(pLo, aLo)
            let borrow := gt(aLo, pLo)
            let rHi := sub(sub(pHi, aHi), borrow)

            // Write 48 bytes big-endian: 16 bytes hi then 32 bytes lo
            mstore(add(result, 0x20), shl(128, rHi))
            mstore(add(result, 0x30), rLo)
        }
    }

    /// @notice (a * b) mod p — fully inlined, no memory allocations for intermediates.
    function mul(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // ── Load a as (a1:a0) where a = a1*2^256 + a0, a1 ≤ 128 bits ──
            let aLen := mload(a)
            let a0 := 0
            let a1 := 0
            if gt(aLen, 31) {
                a0 := mload(add(a, add(0x20, sub(aLen, 32))))
                let hiB := sub(aLen, 32)
                if gt(hiB, 0) { a1 := shr(mul(sub(32, hiB), 8), mload(add(a, 0x20))) }
            }
            if and(gt(aLen, 0), lt(aLen, 32)) { a0 := shr(mul(sub(32, aLen), 8), mload(add(a, 0x20))) }
            if eq(aLen, 32) { a0 := mload(add(a, 0x20)) }

            // ── Load b as (b1:b0) ──
            let bLen := mload(b)
            let b0 := 0
            let b1 := 0
            if gt(bLen, 31) {
                b0 := mload(add(b, add(0x20, sub(bLen, 32))))
                let hiB := sub(bLen, 32)
                if gt(hiB, 0) { b1 := shr(mul(sub(32, hiB), 8), mload(add(b, 0x20))) }
            }
            if and(gt(bLen, 0), lt(bLen, 32)) { b0 := shr(mul(sub(32, bLen), 8), mload(add(b, 0x20))) }
            if eq(bLen, 32) { b0 := mload(add(b, 0x20)) }

            // ── Schoolbook multiply: product = (r2:r1:r0) ──
            // a0*b0 → (hi0:lo0)
            let lo0 := mul(a0, b0)
            let mm0 := mulmod(a0, b0, not(0))
            let hi0 := sub(sub(mm0, lo0), lt(mm0, lo0))

            // a1*b0 → (hi1:lo1), max 384 bits since a1 ≤ 128 bits
            let lo1 := mul(a1, b0)
            let mm1 := mulmod(a1, b0, not(0))
            let hi1 := sub(sub(mm1, lo1), lt(mm1, lo1))

            // a0*b1 → (hi2:lo2)
            let lo2 := mul(a0, b1)
            let mm2 := mulmod(a0, b1, not(0))
            let hi2 := sub(sub(mm2, lo2), lt(mm2, lo2))

            // a1*b1 → fits in 256 bits since both ≤ 128 bits
            let mid_top := mul(a1, b1)

            // Accumulate into (r2:r1:r0)
            let r0 := lo0
            // r1 = hi0 + lo1 + lo2
            let r1 := add(hi0, lo1)
            let c := lt(r1, hi0)
            let r1b := add(r1, lo2)
            c := add(c, lt(r1b, r1))
            r1 := r1b
            // r2 = hi1 + hi2 + mid_top + carry
            let r2 := add(add(hi1, hi2), add(mid_top, c))

            // ── Reduce (r2:r1:r0) mod p using Knuth Algorithm D ──
            // p = (p1:p0), little-endian 2-limb
            let p1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let p0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // Normalize: shift left by 127 so top limb of divisor has MSB set
            let shift := 127
            let invShift := 129  // 256 - shift

            // Shift divisor v = (v1:v0)
            let v1 := or(shl(shift, p1), shr(invShift, p0))
            let v0 := shl(shift, p0)

            // Shift dividend u = (u3:u2:u1:u0) from (r2:r1:r0)
            let u3 := shr(invShift, r2)
            let u2 := or(shl(shift, r2), shr(invShift, r1))
            let u1 := or(shl(shift, r1), shr(invShift, r0))
            let u0 := shl(shift, r0)

            // --- Knuth Algorithm D: two iterations (j=1, j=0) ---
            // We inline div512by256 for qHat estimation.

            // Helper: div512by256 computes (hi:lo) / d -> (q, rem)
            // We use the same algorithm as LimbMath.div512by256.

            // ====== Iteration j=1: estimate from (u3:u2) / v1 ======
            {
                let qHat := 0
                let rHat := 0

                // Estimate qHat
                switch lt(u3, v1)
                case 1 {
                    // Normal case: u3 < v1, do 512/256 division
                    switch iszero(u3)
                    case 1 {
                        qHat := div(u2, v1)
                        rHat := mod(u2, v1)
                    }
                    default {
                        // div512by256(u3, u2, v1)
                        let r256 := addmod(mod(not(0), v1), 1, v1)
                        rHat := addmod(mulmod(u3, r256, v1), u2, v1)
                        let lo_e := sub(u2, rHat)
                        let hi_e := sub(u3, lt(u2, rHat))
                        let twos := and(v1, sub(0, v1))
                        let dd := div(v1, twos)
                        lo_e := div(lo_e, twos)
                        let flip := add(div(sub(0, twos), twos), 1)
                        lo_e := or(lo_e, mul(hi_e, flip))
                        let dinv := xor(mul(3, dd), 2)
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        qHat := mul(lo_e, dinv)
                    }

                    // Refine: while qHat * v0 > (rHat : u1)
                    {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u1))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }
                default {
                    // u3 >= v1: qHat = MAX, rHat = u2 + v1 (may overflow)
                    qHat := not(0)
                    rHat := add(u2, v1)
                    // Refine only if rHat didn't overflow
                    if iszero(lt(rHat, u2)) {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u1))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }

                // Multiply qHat * (v1:v0) => (prd2:prd1:prd0)
                // qHat * v0
                let qv0Lo := mul(qHat, v0)
                let qv0MM := mulmod(qHat, v0, not(0))
                let qv0Hi := sub(sub(qv0MM, qv0Lo), lt(qv0MM, qv0Lo))
                // qHat * v1
                let qv1Lo := mul(qHat, v1)
                let qv1MM := mulmod(qHat, v1, not(0))
                let qv1Hi := sub(sub(qv1MM, qv1Lo), lt(qv1MM, qv1Lo))
                // prd = (qv1Hi : qv0Hi+qv1Lo : qv0Lo)
                let prd0 := qv0Lo
                let prd1 := add(qv0Hi, qv1Lo)
                let prd2 := add(qv1Hi, lt(prd1, qv0Hi))

                // Subtract from u at position j=1: u[1..3] -= prd[0..2]
                let d1 := sub(u1, prd0)
                let bw := gt(prd0, u1)
                let tmp := sub(u2, prd1)
                let bw2 := lt(u2, prd1)
                let d2 := sub(tmp, bw)
                bw2 := or(bw2, gt(bw, tmp))
                let d3 := sub(u3, add(prd2, bw2))
                let negative := gt(add(prd2, bw2), u3)
                // Also check: if prd2+bw2 == u3 but there was further underflow
                // Actually: negative if d3 wrapped. Since u3 was small, check if d3 > u3
                // More robust: check high bit after subtraction
                // d3 should be 0 if correct. If negative, d3 wrapped to huge value.
                negative := or(negative, and(eq(add(prd2, bw2), u3), 0))
                // Simplify: negative = (prd2 + bw2 > u3)
                // But we need to handle prd2 + bw2 overflow too. Since prd2 is from 128-bit * 256-bit, it could be large.
                // Actually just check if d3 has high bit set or is nonzero-large...
                // For correctness: negative iff the true 3-limb subtract went below zero.
                // Since after the loop u should have at most 2 limbs of remainder, d3 should be 0.
                // If d3 != 0 and d3 is huge (wrapped), it's negative.
                // The safest check: was there a borrow out of the top?
                // borrow_out = (prd2 + bw2) > u3, OR (prd2 + bw2 == u3 is fine, d3=0, not negative)
                // We already set negative = gt(add(prd2, bw2), u3) but add can overflow.
                // Let's be careful:
                let totalBorrow := add(prd2, bw2)
                let borrowOverflow := lt(totalBorrow, prd2) // add(prd2,bw2) overflowed
                negative := or(borrowOverflow, gt(totalBorrow, u3))

                if negative {
                    // Add back v at position j=1
                    let s1 := add(d1, v0)
                    let cc := lt(s1, d1)
                    let s2 := add(d2, v1)
                    let cc2 := lt(s2, d2)
                    s2 := add(s2, cc)
                    cc2 := or(cc2, lt(s2, cc))
                    d3 := add(d3, cc2)
                    d1 := s1
                    d2 := s2
                }

                u0 := u0
                u1 := d1
                u2 := d2
                u3 := d3
            }

            // ====== Iteration j=0: estimate from (u2:u1) / v1 ======
            {
                let qHat := 0
                let rHat := 0

                switch lt(u2, v1)
                case 1 {
                    switch iszero(u2)
                    case 1 {
                        qHat := div(u1, v1)
                        rHat := mod(u1, v1)
                    }
                    default {
                        let r256 := addmod(mod(not(0), v1), 1, v1)
                        rHat := addmod(mulmod(u2, r256, v1), u1, v1)
                        let lo_e := sub(u1, rHat)
                        let hi_e := sub(u2, lt(u1, rHat))
                        let twos := and(v1, sub(0, v1))
                        let dd := div(v1, twos)
                        lo_e := div(lo_e, twos)
                        let flip := add(div(sub(0, twos), twos), 1)
                        lo_e := or(lo_e, mul(hi_e, flip))
                        let dinv := xor(mul(3, dd), 2)
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        qHat := mul(lo_e, dinv)
                    }

                    {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u0))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }
                default {
                    qHat := not(0)
                    rHat := add(u1, v1)
                    if iszero(lt(rHat, u1)) {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u0))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }

                // Multiply qHat * (v1:v0) => (prd2:prd1:prd0)
                let qv0Lo := mul(qHat, v0)
                let qv0MM := mulmod(qHat, v0, not(0))
                let qv0Hi := sub(sub(qv0MM, qv0Lo), lt(qv0MM, qv0Lo))
                let qv1Lo := mul(qHat, v1)
                let qv1MM := mulmod(qHat, v1, not(0))
                let qv1Hi := sub(sub(qv1MM, qv1Lo), lt(qv1MM, qv1Lo))
                let prd0 := qv0Lo
                let prd1 := add(qv0Hi, qv1Lo)
                let prd2 := add(qv1Hi, lt(prd1, qv0Hi))

                // Subtract from u at position j=0: u[0..2] -= prd[0..2]
                let d0 := sub(u0, prd0)
                let bw := gt(prd0, u0)
                let tmp := sub(u1, prd1)
                let bw2 := lt(u1, prd1)
                let dd1 := sub(tmp, bw)
                bw2 := or(bw2, gt(bw, tmp))
                let dd2 := sub(u2, add(prd2, bw2))
                let totalBorrow := add(prd2, bw2)
                let borrowOverflow := lt(totalBorrow, prd2)
                let negative := or(borrowOverflow, gt(totalBorrow, u2))

                if negative {
                    let s0 := add(d0, v0)
                    let cc := lt(s0, d0)
                    let s1 := add(dd1, v1)
                    let cc2 := lt(s1, dd1)
                    s1 := add(s1, cc)
                    cc2 := or(cc2, lt(s1, cc))
                    d0 := s0
                    dd1 := s1
                }

                u0 := d0
                u1 := dd1
            }

            // Denormalize: shift right by 127
            let rem0 := or(shr(shift, u0), shl(invShift, u1))
            let rem1 := shr(shift, u1)

            // Final conditional subtract if rem >= p
            let gte := or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0))))
            if gte {
                let nr := sub(rem0, p0)
                rem1 := sub(sub(rem1, p1), gt(p0, rem0))
                rem0 := nr
            }

            // Store result (48 bytes big-endian: 16 bytes hi + 32 bytes lo)
            mstore(add(result, 0x20), shl(128, rem1))
            mstore(add(result, 0x30), rem0)
        }
    }

    /// @notice a^2 mod p — exploits a==b symmetry: only 3 partial products instead of 4.
    function sqr(bytes memory a) internal pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // ── Load a as (a1:a0) where a = a1*2^256 + a0, a1 ≤ 128 bits ──
            let aLen := mload(a)
            let a0 := 0
            let a1 := 0
            if gt(aLen, 31) {
                a0 := mload(add(a, add(0x20, sub(aLen, 32))))
                let hiB := sub(aLen, 32)
                if gt(hiB, 0) { a1 := shr(mul(sub(32, hiB), 8), mload(add(a, 0x20))) }
            }
            if and(gt(aLen, 0), lt(aLen, 32)) { a0 := shr(mul(sub(32, aLen), 8), mload(add(a, 0x20))) }
            if eq(aLen, 32) { a0 := mload(add(a, 0x20)) }

            // ── Squaring: product = (r2:r1:r0) using 3 partial products ──
            // a0*a0 → (hi0:lo0)
            let lo0 := mul(a0, a0)
            let mm0 := mulmod(a0, a0, not(0))
            let hi0 := sub(sub(mm0, lo0), lt(mm0, lo0))

            // a1*a0 → (hi1:lo1), then double it
            let lo1 := mul(a1, a0)
            let mm1 := mulmod(a1, a0, not(0))
            let hi1 := sub(sub(mm1, lo1), lt(mm1, lo1))
            // Double: (hi1:lo1) << 1
            hi1 := or(shl(1, hi1), shr(255, lo1))
            lo1 := shl(1, lo1)

            // a1*a1 → fits in 256 bits since a1 ≤ 128 bits
            let mid_top := mul(a1, a1)

            // Accumulate into (r2:r1:r0)
            let r0 := lo0
            // r1 = hi0 + lo1
            let r1 := add(hi0, lo1)
            let c := lt(r1, hi0)
            // r2 = hi1 + mid_top + carry
            let r2 := add(add(hi1, mid_top), c)

            // ── Reduce (r2:r1:r0) mod p using Knuth Algorithm D ──
            // p = (p1:p0), little-endian 2-limb
            let p1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let p0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // Normalize: shift left by 127 so top limb of divisor has MSB set
            let shift := 127
            let invShift := 129  // 256 - shift

            // Shift divisor v = (v1:v0)
            let v1 := or(shl(shift, p1), shr(invShift, p0))
            let v0 := shl(shift, p0)

            // Shift dividend u = (u3:u2:u1:u0) from (r2:r1:r0)
            let u3 := shr(invShift, r2)
            let u2 := or(shl(shift, r2), shr(invShift, r1))
            let u1 := or(shl(shift, r1), shr(invShift, r0))
            let u0 := shl(shift, r0)

            // ====== Iteration j=1: estimate from (u3:u2) / v1 ======
            {
                let qHat := 0
                let rHat := 0

                switch lt(u3, v1)
                case 1 {
                    switch iszero(u3)
                    case 1 {
                        qHat := div(u2, v1)
                        rHat := mod(u2, v1)
                    }
                    default {
                        let r256 := addmod(mod(not(0), v1), 1, v1)
                        rHat := addmod(mulmod(u3, r256, v1), u2, v1)
                        let lo_e := sub(u2, rHat)
                        let hi_e := sub(u3, lt(u2, rHat))
                        let twos := and(v1, sub(0, v1))
                        let dd := div(v1, twos)
                        lo_e := div(lo_e, twos)
                        let flip := add(div(sub(0, twos), twos), 1)
                        lo_e := or(lo_e, mul(hi_e, flip))
                        let dinv := xor(mul(3, dd), 2)
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        qHat := mul(lo_e, dinv)
                    }

                    {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u1))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }
                default {
                    qHat := not(0)
                    rHat := add(u2, v1)
                    if iszero(lt(rHat, u2)) {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u1))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }

                let qv0Lo := mul(qHat, v0)
                let qv0MM := mulmod(qHat, v0, not(0))
                let qv0Hi := sub(sub(qv0MM, qv0Lo), lt(qv0MM, qv0Lo))
                let qv1Lo := mul(qHat, v1)
                let qv1MM := mulmod(qHat, v1, not(0))
                let qv1Hi := sub(sub(qv1MM, qv1Lo), lt(qv1MM, qv1Lo))
                let prd0 := qv0Lo
                let prd1 := add(qv0Hi, qv1Lo)
                let prd2 := add(qv1Hi, lt(prd1, qv0Hi))

                let d1 := sub(u1, prd0)
                let bw := gt(prd0, u1)
                let tmp := sub(u2, prd1)
                let bw2 := lt(u2, prd1)
                let d2 := sub(tmp, bw)
                bw2 := or(bw2, gt(bw, tmp))
                let d3 := sub(u3, add(prd2, bw2))
                let totalBorrow := add(prd2, bw2)
                let borrowOverflow := lt(totalBorrow, prd2)
                let negative := or(borrowOverflow, gt(totalBorrow, u3))

                if negative {
                    let s1 := add(d1, v0)
                    let cc := lt(s1, d1)
                    let s2 := add(d2, v1)
                    let cc2 := lt(s2, d2)
                    s2 := add(s2, cc)
                    cc2 := or(cc2, lt(s2, cc))
                    d3 := add(d3, cc2)
                    d1 := s1
                    d2 := s2
                }

                u0 := u0
                u1 := d1
                u2 := d2
                u3 := d3
            }

            // ====== Iteration j=0: estimate from (u2:u1) / v1 ======
            {
                let qHat := 0
                let rHat := 0

                switch lt(u2, v1)
                case 1 {
                    switch iszero(u2)
                    case 1 {
                        qHat := div(u1, v1)
                        rHat := mod(u1, v1)
                    }
                    default {
                        let r256 := addmod(mod(not(0), v1), 1, v1)
                        rHat := addmod(mulmod(u2, r256, v1), u1, v1)
                        let lo_e := sub(u1, rHat)
                        let hi_e := sub(u2, lt(u1, rHat))
                        let twos := and(v1, sub(0, v1))
                        let dd := div(v1, twos)
                        lo_e := div(lo_e, twos)
                        let flip := add(div(sub(0, twos), twos), 1)
                        lo_e := or(lo_e, mul(hi_e, flip))
                        let dinv := xor(mul(3, dd), 2)
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        dinv := mul(dinv, sub(2, mul(dd, dinv)))
                        qHat := mul(lo_e, dinv)
                    }

                    {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u0))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }
                default {
                    qHat := not(0)
                    rHat := add(u1, v1)
                    if iszero(lt(rHat, u1)) {
                        let qvLo := mul(qHat, v0)
                        let qvMM := mulmod(qHat, v0, not(0))
                        let qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        for {} or(gt(qvHi, rHat), and(eq(qvHi, rHat), gt(qvLo, u0))) {} {
                            qHat := sub(qHat, 1)
                            rHat := add(rHat, v1)
                            if lt(rHat, v1) { break }
                            qvLo := mul(qHat, v0)
                            qvMM := mulmod(qHat, v0, not(0))
                            qvHi := sub(sub(qvMM, qvLo), lt(qvMM, qvLo))
                        }
                    }
                }

                let qv0Lo := mul(qHat, v0)
                let qv0MM := mulmod(qHat, v0, not(0))
                let qv0Hi := sub(sub(qv0MM, qv0Lo), lt(qv0MM, qv0Lo))
                let qv1Lo := mul(qHat, v1)
                let qv1MM := mulmod(qHat, v1, not(0))
                let qv1Hi := sub(sub(qv1MM, qv1Lo), lt(qv1MM, qv1Lo))
                let prd0 := qv0Lo
                let prd1 := add(qv0Hi, qv1Lo)
                let prd2 := add(qv1Hi, lt(prd1, qv0Hi))

                let d0 := sub(u0, prd0)
                let bw := gt(prd0, u0)
                let tmp := sub(u1, prd1)
                let bw2 := lt(u1, prd1)
                let dd1 := sub(tmp, bw)
                bw2 := or(bw2, gt(bw, tmp))
                let dd2 := sub(u2, add(prd2, bw2))
                let totalBorrow := add(prd2, bw2)
                let borrowOverflow := lt(totalBorrow, prd2)
                let negative := or(borrowOverflow, gt(totalBorrow, u2))

                if negative {
                    let s0 := add(d0, v0)
                    let cc := lt(s0, d0)
                    let s1 := add(dd1, v1)
                    let cc2 := lt(s1, dd1)
                    s1 := add(s1, cc)
                    cc2 := or(cc2, lt(s1, cc))
                    d0 := s0
                    dd1 := s1
                }

                u0 := d0
                u1 := dd1
            }

            // Denormalize: shift right by 127
            let rem0 := or(shr(shift, u0), shl(invShift, u1))
            let rem1 := shr(shift, u1)

            // Final conditional subtract if rem >= p
            let gte := or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0))))
            if gte {
                let nr := sub(rem0, p0)
                rem1 := sub(sub(rem1, p1), gt(p0, rem0))
                rem0 := nr
            }

            // Store result (48 bytes big-endian: 16 bytes hi + 32 bytes lo)
            mstore(add(result, 0x20), shl(128, rem1))
            mstore(add(result, 0x30), rem0)
        }
    }

    /// @notice a^{-1} mod p via Fermat's little theorem: a^(p-2) mod p.
    function inv(bytes memory a) internal pure returns (bytes memory) {
        return _modexp(a, P_MINUS_2);
    }

    /// @notice Square root: a^{(p+1)/4} mod p. Valid since p = 3 mod 4.
    /// @dev Caller must verify the result (square it back) to confirm a is a QR.
    function sqrt(bytes memory a) internal pure returns (bytes memory) {
        return _modexp(a, P_PLUS_1_DIV_4);
    }

    /// @notice Returns true if a is a quadratic residue mod p.
    function isSquare(bytes memory a) internal pure returns (bool) {
        if (LimbMath.isZeroBytes(a)) return true;
        bytes memory root = sqrt(a);
        bytes memory check = sqr(root);
        return keccak256(check) == keccak256(a);
    }

    /// @notice sgn0: returns a mod 2 (the parity bit / LSB of the big-endian representation).
    function sgn0(bytes memory a) internal pure returns (uint256) {
        if (a.length == 0) return 0;
        return uint8(a[a.length - 1]) & 1;
    }

    /// @notice Returns true if a == 0.
    function isZero(bytes memory a) internal pure returns (bool) {
        return LimbMath.isZeroBytes(a);
    }

    /// @notice Returns true if a == b (by hash comparison).
    function eq(bytes memory a, bytes memory b) internal pure returns (bool) {
        return keccak256(a) == keccak256(b);
    }

    /// @notice Encode a uint256 as a 48-byte big-endian field element.
    function fromUint256(uint256 x) internal pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // The uint256 value occupies the last 32 bytes of the 48-byte result.
            mstore(add(result, 0x30), x)
        }
    }

    /// @notice Square-root ratio per RFC 9380, Appendix F.2.1.2.
    /// @param u Numerator field element.
    /// @param v Denominator field element.
    /// @param sqrtMinusZ Pre-computed sqrt(-Z) for the suite.
    /// @return isQR True if u/v is a quadratic residue.
    /// @return y The square root (y1 if QR, y2 otherwise).
    function sqrtRatio(
        bytes memory u,
        bytes memory v,
        bytes memory sqrtMinusZ
    ) internal pure returns (bool isQR, bytes memory y) {
        // c1 = (p - 3) / 4
        // tv1 = v^2
        bytes memory tv1 = sqr(v);
        // tv2 = u * v
        bytes memory tv2 = mul(u, v);
        // tv1 = tv1 * tv2  (= u * v^3)
        tv1 = mul(tv1, tv2);
        // y1 = tv1^c1
        bytes memory y1 = _modexp(tv1, P_MINUS_3_DIV_4);
        // y1 = y1 * tv2   (= y1 * u * v)
        y1 = mul(y1, tv2);

        // y2 = y1 * sqrtMinusZ
        bytes memory y2 = mul(y1, sqrtMinusZ);

        // tv3 = y1^2 * v
        bytes memory tv3 = mul(sqr(y1), v);

        // isQR = (tv3 == u)
        isQR = eq(tv3, u);

        // y = isQR ? y1 : y2
        y = isQR ? y1 : y2;
    }

    // ── Montgomery constants for 2-limb modular exponentiation ──────

    // n0inv = -p[0]^{-1} mod 2^256
    uint256 constant N0INV = 0x19ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd;

    // R^2 mod p = (2^512)^2 mod p, as 2 limbs (little-endian)
    uint256 constant R2_LO = 0xcc0868ce6a76590c76e5bc3ff951c543861c23693de6a351fb73eaead26ebe58;
    uint256 constant R2_HI = 0x0010a8c1a49a064ff0a85a3f35446d0b;

    // p as 2 limbs (little-endian)
    uint256 constant N0 = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint256 constant N1 = 0x1a0111ea397fe69a4b1ba7b6434bacd7;

    /// @dev Specialized 2-limb Montgomery exponentiation for the BLS12-381 base field.
    ///      base^exponent mod p, where p is the BLS12-381 base field modulus.
    function _modexp(bytes memory base, bytes memory exponent) private pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // Allocate 4 words of scratch: aM0, aM1, rM0, rM1
            let scratch := mload(0x40)
            mstore(0x40, add(scratch, 0x80))
            // ── montMul2: 2-limb CIOS with hardcoded constants ──
            // Constants are inlined to avoid stack pressure.
            function montMul2(x0, x1, y0, y1) -> z0, z1 {
                let t0 := 0
                let t1 := 0
                let t2 := 0

                // ── Iteration i=0: process x0 ──
                {
                    let lo := mul(x0, y0)
                    let hi := sub(sub(mulmod(x0, y0, not(0)), lo), lt(mulmod(x0, y0, not(0)), lo))
                    t0 := lo
                    let carry := hi

                    lo := mul(x0, y1)
                    hi := sub(sub(mulmod(x0, y1, not(0)), lo), lt(mulmod(x0, y1, not(0)), lo))
                    let s := add(lo, carry)
                    t1 := s
                    t2 := add(hi, lt(s, lo))
                }

                // Reduce
                let m := mul(t0, 0x19ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd)
                {
                    let _n0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                    let lo := mul(m, _n0)
                    let hi := sub(sub(mulmod(m, _n0, not(0)), lo), lt(mulmod(m, _n0, not(0)), lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))

                    let _n1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                    lo := mul(m, _n1)
                    hi := sub(sub(mulmod(m, _n1, not(0)), lo), lt(mulmod(m, _n1, not(0)), lo))
                    s := add(t1, lo)
                    let c1 := lt(s, t1)
                    let s2 := add(s, carry)
                    let c2 := lt(s2, s)
                    t0 := s2
                    t1 := add(t2, add(hi, add(c1, c2)))
                    t2 := 0
                }

                // ── Iteration i=1: process x1 ──
                {
                    let lo := mul(x1, y0)
                    let hi := sub(sub(mulmod(x1, y0, not(0)), lo), lt(mulmod(x1, y0, not(0)), lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))
                    t0 := s

                    lo := mul(x1, y1)
                    hi := sub(sub(mulmod(x1, y1, not(0)), lo), lt(mulmod(x1, y1, not(0)), lo))
                    s := add(t1, lo)
                    let c1 := lt(s, t1)
                    let s2 := add(s, carry)
                    let c2 := lt(s2, s)
                    t1 := s2
                    t2 := add(hi, add(c1, c2))
                }

                // Reduce
                m := mul(t0, 0x19ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd)
                {
                    let _n0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                    let lo := mul(m, _n0)
                    let hi := sub(sub(mulmod(m, _n0, not(0)), lo), lt(mulmod(m, _n0, not(0)), lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))

                    let _n1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                    lo := mul(m, _n1)
                    hi := sub(sub(mulmod(m, _n1, not(0)), lo), lt(mulmod(m, _n1, not(0)), lo))
                    s := add(t1, lo)
                    let c1 := lt(s, t1)
                    let s2 := add(s, carry)
                    let c2 := lt(s2, s)
                    z0 := s2
                    z1 := add(t2, add(hi, add(c1, c2)))
                }

                // Final conditional subtraction
                {
                    let _n0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                    let _n1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                    let doSub := or(gt(z1, _n1), and(eq(z1, _n1), iszero(lt(z0, _n0))))
                    if doSub {
                        let newZ0 := sub(z0, _n0)
                        z1 := sub(sub(z1, _n1), gt(_n0, z0))
                        z0 := newZ0
                    }
                }
            }

            // ── Load base as 2 limbs (little-endian): (a0, a1) ──
            let a0 := 0
            let a1 := 0
            {
                let baseLen := mload(base)
                if gt(baseLen, 31) {
                    a0 := mload(add(base, add(0x20, sub(baseLen, 32))))
                    let hiB := sub(baseLen, 32)
                    if gt(hiB, 0) { a1 := shr(mul(sub(32, hiB), 8), mload(add(base, 0x20))) }
                }
                if and(gt(baseLen, 0), lt(baseLen, 32)) { a0 := shr(mul(sub(32, baseLen), 8), mload(add(base, 0x20))) }
                if eq(baseLen, 32) { a0 := mload(add(base, 0x20)) }
            }

            // ── Convert base to Montgomery form: aM = montMul(a, R2) ──
            // Store aM in scratch memory at scratch+0x00, scratch+0x20
            {
                let aM0, aM1 := montMul2(
                    a0, a1,
                    0xcc0868ce6a76590c76e5bc3ff951c543861c23693de6a351fb73eaead26ebe58,
                    0x0010a8c1a49a064ff0a85a3f35446d0b
                )
                mstore(scratch, aM0)
                mstore(add(scratch, 0x20), aM1)
            }

            // ── Initialize rM ──
            // Store rM in scratch memory at scratch+0x40, scratch+0x60
            let expLen := mload(exponent)
            let expStart := add(exponent, 0x20)

            // Skip leading zero bytes
            let startByte := 0
            for {} lt(startByte, expLen) { startByte := add(startByte, 1) } {
                if byte(0, mload(add(expStart, startByte))) { break }
            }

            // Default rM = montMul(1, R2) = R mod n (in case exponent is 0)
            {
                let rM0, rM1 := montMul2(
                    1, 0,
                    0xcc0868ce6a76590c76e5bc3ff951c543861c23693de6a351fb73eaead26ebe58,
                    0x0010a8c1a49a064ff0a85a3f35446d0b
                )
                mstore(add(scratch, 0x40), rM0)
                mstore(add(scratch, 0x60), rM1)
            }

            if lt(startByte, expLen) {
                // Set rM = aM (the MSB is 1)
                mstore(add(scratch, 0x40), mload(scratch))
                mstore(add(scratch, 0x60), mload(add(scratch, 0x20)))

                // Process first non-zero byte
                let b := byte(0, mload(add(expStart, startByte)))
                let topBit := 7
                for {} gt(topBit, 0) { topBit := sub(topBit, 1) } {
                    if and(shr(topBit, b), 1) { break }
                }

                // Process remaining bits of first byte (topBit-1 down to 0)
                if gt(topBit, 0) {
                    let bit := sub(topBit, 1)
                    for {} 1 {} {
                        // Square: rM = montMul(rM, rM)
                        {
                            let r0 := mload(add(scratch, 0x40))
                            let r1 := mload(add(scratch, 0x60))
                            let z0, z1 := montMul2(r0, r1, r0, r1)
                            mstore(add(scratch, 0x40), z0)
                            mstore(add(scratch, 0x60), z1)
                        }
                        // Multiply if bit set
                        if and(shr(bit, b), 1) {
                            let z0, z1 := montMul2(mload(add(scratch, 0x40)), mload(add(scratch, 0x60)), mload(scratch), mload(add(scratch, 0x20)))
                            mstore(add(scratch, 0x40), z0)
                            mstore(add(scratch, 0x60), z1)
                        }
                        if iszero(bit) { break }
                        bit := sub(bit, 1)
                    }
                }

                // Process remaining bytes
                for { let byteIdx := add(startByte, 1) } lt(byteIdx, expLen) { byteIdx := add(byteIdx, 1) } {
                    b := byte(0, mload(add(expStart, byteIdx)))

                    // Process 8 bits per byte
                    let bit := 8
                    for {} gt(bit, 0) {} {
                        bit := sub(bit, 1)
                        // Square
                        {
                            let r0 := mload(add(scratch, 0x40))
                            let r1 := mload(add(scratch, 0x60))
                            let z0, z1 := montMul2(r0, r1, r0, r1)
                            mstore(add(scratch, 0x40), z0)
                            mstore(add(scratch, 0x60), z1)
                        }
                        // Multiply if bit set
                        if and(shr(bit, b), 1) {
                            let z0, z1 := montMul2(mload(add(scratch, 0x40)), mload(add(scratch, 0x60)), mload(scratch), mload(add(scratch, 0x20)))
                            mstore(add(scratch, 0x40), z0)
                            mstore(add(scratch, 0x60), z1)
                        }
                    }
                }
            }

            // ── Exit Montgomery form: result = montMul(rM, 1) ──
            {
                let z0, z1 := montMul2(mload(add(scratch, 0x40)), mload(add(scratch, 0x60)), 1, 0)
                // Store as 48-byte big-endian
                mstore(add(result, 0x20), shl(128, z1))
                mstore(add(result, 0x30), z0)
            }
        }
    }
}
