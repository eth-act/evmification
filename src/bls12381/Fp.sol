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

    // ── Arithmetic operations ────────────────────────────────────────

    /// @dev Load a big-endian Fp element as (hi:lo) 128/256-bit limbs.
    ///      Fast path for the canonical 48-byte encoding every constructor in
    ///      this codebase produces; general fallback for any length <= 48.
    ///      Used on cold paths only — the hot ops (add/sub/neg/mul/sqr) inline
    ///      this same load, which measures faster in large callers.
    function _loadFp(bytes memory x) private pure returns (uint256 hi, uint256 lo) {
        assembly {
            switch eq(mload(x), 48)
            case 1 {
                hi := shr(128, mload(add(x, 0x20)))
                lo := mload(add(x, 0x30))
            }
            default {
                let len := mload(x)
                if gt(len, 31) {
                    lo := mload(add(x, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { hi := shr(mul(sub(32, hb), 8), mload(add(x, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { lo := shr(mul(sub(32, len), 8), mload(add(x, 0x20))) }
                if eq(len, 32) { lo := mload(add(x, 0x20)) }
            }
        }
    }

    /// @dev Allocate a 48-byte element and store (hi:lo) into it big-endian.
    ///      Skips new bytes' zero-initialization: all 48 data bytes are written.
    function _pack(uint256 hi, uint256 lo) private pure returns (bytes memory result) {
        assembly {
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)
            mstore(add(result, 0x20), shl(128, hi))
            mstore(add(result, 0x30), lo)
        }
    }

    /// @notice (a + b) mod p.
    /// @dev Uses conditional subtraction instead of modexp for reduction.
    function add(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        // Monolithic assembly (loads/alloc not shared via helpers): measured
        // faster than helper composition, which via-ir stops inlining in
        // large callers.
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

            // Load a as (aHi:aLo) — 128-bit hi, 256-bit lo
            let aLo := 0
            let aHi := 0
            switch eq(mload(a), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                aHi := shr(128, mload(add(a, 0x20)))
                aLo := mload(add(a, 0x30))
            }
            default {
                let len := mload(a)
                if gt(len, 31) {
                    aLo := mload(add(a, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { aHi := shr(mul(sub(32, hb), 8), mload(add(a, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { aLo := shr(mul(sub(32, len), 8), mload(add(a, 0x20))) }
                if eq(len, 32) { aLo := mload(add(a, 0x20)) }
            }

            // Load b as (bHi:bLo)
            let bLo := 0
            let bHi := 0
            switch eq(mload(b), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                bHi := shr(128, mload(add(b, 0x20)))
                bLo := mload(add(b, 0x30))
            }
            default {
                let len := mload(b)
                if gt(len, 31) {
                    bLo := mload(add(b, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { bHi := shr(mul(sub(32, hb), 8), mload(add(b, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { bLo := shr(mul(sub(32, len), 8), mload(add(b, 0x20))) }
                if eq(len, 32) { bLo := mload(add(b, 0x20)) }
            }

            // sum = a + b (with carry into hi)
            let sLo := add(aLo, bLo)
            let sHi := add(add(aHi, bHi), lt(sLo, aLo))

            // Conditional subtract p if sum >= p
            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            if or(gt(sHi, pHi), and(eq(sHi, pHi), iszero(lt(sLo, pLo)))) {
                let newLo := sub(sLo, pLo)
                sHi := sub(sHi, add(pHi, gt(pLo, sLo)))
                sLo := newLo
            }

            mstore(add(result, 0x20), shl(128, sHi))
            mstore(add(result, 0x30), sLo)
        }
    }

    /// @notice (a - b) mod p.
    /// @dev Direct subtraction with conditional add of p.
    function sub(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

            // Load a as (aHi:aLo)
            let aLo := 0
            let aHi := 0
            switch eq(mload(a), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                aHi := shr(128, mload(add(a, 0x20)))
                aLo := mload(add(a, 0x30))
            }
            default {
                let len := mload(a)
                if gt(len, 31) {
                    aLo := mload(add(a, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { aHi := shr(mul(sub(32, hb), 8), mload(add(a, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { aLo := shr(mul(sub(32, len), 8), mload(add(a, 0x20))) }
                if eq(len, 32) { aLo := mload(add(a, 0x20)) }
            }

            // Load b as (bHi:bLo)
            let bLo := 0
            let bHi := 0
            switch eq(mload(b), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                bHi := shr(128, mload(add(b, 0x20)))
                bLo := mload(add(b, 0x30))
            }
            default {
                let len := mload(b)
                if gt(len, 31) {
                    bLo := mload(add(b, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { bHi := shr(mul(sub(32, hb), 8), mload(add(b, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { bLo := shr(mul(sub(32, len), 8), mload(add(b, 0x20))) }
                if eq(len, 32) { bLo := mload(add(b, 0x20)) }
            }

            // diff = a - b (with borrow)
            let dLo := sub(aLo, bLo)
            let dHi := sub(sub(aHi, bHi), gt(bLo, aLo))

            // If underflow (a < b), add p. Both a, b < p < 2^381, so their hi
            // parts are < 2^128; on underflow dHi wraps to a huge value.
            if gt(dHi, 0x1a0111ea397fe69a4b1ba7b6434bacd7) {
                let newLo := add(dLo, 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
                dHi := add(add(dHi, 0x1a0111ea397fe69a4b1ba7b6434bacd7), lt(newLo, dLo))
                dLo := newLo
            }

            mstore(add(result, 0x20), shl(128, dHi))
            mstore(add(result, 0x30), dLo)
        }
    }

    /// @notice -a mod p, computed as p - a.
    function neg(bytes memory a) internal pure returns (bytes memory result) {
        if (LimbMath.isZeroBytes(a)) {
            return new bytes(48);
        }
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

            // Load a as (aHi:aLo)
            let aLo := 0
            let aHi := 0
            switch eq(mload(a), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                aHi := shr(128, mload(add(a, 0x20)))
                aLo := mload(add(a, 0x30))
            }
            default {
                let len := mload(a)
                if gt(len, 31) {
                    aLo := mload(add(a, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { aHi := shr(mul(sub(32, hb), 8), mload(add(a, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { aLo := shr(mul(sub(32, len), 8), mload(add(a, 0x20))) }
                if eq(len, 32) { aLo := mload(add(a, 0x20)) }
            }

            // p - a
            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
            let rLo := sub(pLo, aLo)
            let rHi := sub(sub(pHi, aHi), gt(aLo, pLo))

            mstore(add(result, 0x20), shl(128, rHi))
            mstore(add(result, 0x30), rLo)
        }
    }

    /// @notice (a * b) mod p — fully inlined, no memory allocations for intermediates.
    function mul(bytes memory a, bytes memory b) internal pure returns (bytes memory result) {
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

            // ── Load a as (a1:a0) where a = a1*2^256 + a0, a1 <= 128 bits ──
            let a0 := 0
            let a1 := 0
            switch eq(mload(a), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                a1 := shr(128, mload(add(a, 0x20)))
                a0 := mload(add(a, 0x30))
            }
            default {
                let len := mload(a)
                if gt(len, 31) {
                    a0 := mload(add(a, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { a1 := shr(mul(sub(32, hb), 8), mload(add(a, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { a0 := shr(mul(sub(32, len), 8), mload(add(a, 0x20))) }
                if eq(len, 32) { a0 := mload(add(a, 0x20)) }
            }

            // ── Load b as (b1:b0) ──
            let b0 := 0
            let b1 := 0
            switch eq(mload(b), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                b1 := shr(128, mload(add(b, 0x20)))
                b0 := mload(add(b, 0x30))
            }
            default {
                let len := mload(b)
                if gt(len, 31) {
                    b0 := mload(add(b, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { b1 := shr(mul(sub(32, hb), 8), mload(add(b, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { b0 := shr(mul(sub(32, len), 8), mload(add(b, 0x20))) }
                if eq(len, 32) { b0 := mload(add(b, 0x20)) }
            }

            // ── Schoolbook multiply: product = (r2:r1:r0) ──
            // a0*b0 -> (hi0:lo0)
            let lo0 := mul(a0, b0)
            let mm0 := mulmod(a0, b0, not(0))
            let hi0 := sub(sub(mm0, lo0), lt(mm0, lo0))

            // a1*b0 -> (hi1:lo1), max 384 bits since a1 <= 128 bits
            let lo1 := mul(a1, b0)
            let mm1 := mulmod(a1, b0, not(0))
            let hi1 := sub(sub(mm1, lo1), lt(mm1, lo1))

            // a0*b1 -> (hi2:lo2)
            let lo2 := mul(a0, b1)
            let mm2 := mulmod(a0, b1, not(0))
            let hi2 := sub(sub(mm2, lo2), lt(mm2, lo2))

            // a1*b1 -> fits in 256 bits since both <= 128 bits
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

            // ── Barrett reduction mod p (fixed modulus) ──
            // NOTE: deliberately duplicated between mul and sqr (keep in sync).
            // A shared helper measured ~7% slower end-to-end: via-ir does not
            // reliably inline it inside large callers like Fp2.mul.
            // mu = floor(2^1024 / p) = (M2:M1:M0), precomputed.
            // q = ((x >> 256) * mu) >> 768 where x = (r2:r1:r0) < p^2.
            // Then r = x - q*p, with r < 3p (at most 2 corrective subtractions;
            // r fits in 512 bits so only the low 2 limbs of q*p are needed).
            let Q0
            let Q1
            {
                let M0 := 0xad397b918f6ff20d533b6c08511c60e2757079ace6bd401859778ceb4dabc4f8
                let M1 := 0x1b82741ff6a0a94bdf4771e0286779d3997167a058f1c07b13e207f56591ba2e
                let M2 := 0x9d835d2f3cc9e45ce28101b0cc7a6ba29

                // Six 256x256->512 partial products of (r1, r2) x (M0, M1, M2)
                let lo00 := mul(r1, M0)
                let mm := mulmod(r1, M0, not(0))
                let hi00 := sub(sub(mm, lo00), lt(mm, lo00))

                let lo01 := mul(r1, M1)
                mm := mulmod(r1, M1, not(0))
                let hi01 := sub(sub(mm, lo01), lt(mm, lo01))

                let lo02 := mul(r1, M2)
                mm := mulmod(r1, M2, not(0))
                let hi02 := sub(sub(mm, lo02), lt(mm, lo02))

                let lo10 := mul(r2, M0)
                mm := mulmod(r2, M0, not(0))
                let hi10 := sub(sub(mm, lo10), lt(mm, lo10))

                let lo11 := mul(r2, M1)
                mm := mulmod(r2, M1, not(0))
                let hi11 := sub(sub(mm, lo11), lt(mm, lo11))

                let lo12 := mul(r2, M2)
                mm := mulmod(r2, M2, not(0))
                let hi12 := sub(sub(mm, lo12), lt(mm, lo12))

                // Product limb 1 = hi00 + lo01 + lo10 (value discarded, carry kept)
                let L := add(hi00, lo01)
                let cA := lt(L, hi00)
                L := add(L, lo10)
                cA := add(cA, lt(L, lo10))

                // Product limb 2 = hi01 + hi10 + lo02 + lo11 + cA (value discarded, carry kept)
                L := add(hi01, hi10)
                let cB := lt(L, hi01)
                L := add(L, lo02)
                cB := add(cB, lt(L, lo02))
                L := add(L, lo11)
                cB := add(cB, lt(L, lo11))
                L := add(L, cA)
                cB := add(cB, lt(L, cA))

                // Product limb 3 = hi02 + hi11 + lo12 + cB -> Q0 (low limb of q)
                Q0 := add(hi02, hi11)
                let cC := lt(Q0, hi02)
                Q0 := add(Q0, lo12)
                cC := add(cC, lt(Q0, lo12))
                Q0 := add(Q0, cB)
                cC := add(cC, lt(Q0, cB))

                // Product limb 4 -> Q1 (high limb of q)
                Q1 := add(hi12, cC)
            }

            let p1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let p0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // r = x - q*p, exact in 512 bits -> only low 2 limbs of q*p needed
            let rem0
            let rem1
            {
                let lo := mul(Q0, p0)
                let mm := mulmod(Q0, p0, not(0))
                let hi := sub(sub(mm, lo), lt(mm, lo))
                // low-2-limb product: B0 = lo, B1 = hi + lo(Q0*p1) + lo(Q1*p0) mod 2^256
                let B1 := add(add(hi, mul(Q0, p1)), mul(Q1, p0))

                rem0 := sub(r0, lo)
                rem1 := sub(sub(r1, B1), lt(r0, lo))
            }

            // Correct: subtract p while rem >= p (at most twice by the Barrett bound)
            if or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0)))) {
                let nr := sub(rem0, p0)
                rem1 := sub(sub(rem1, p1), gt(p0, rem0))
                rem0 := nr
            }
            if or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0)))) {
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
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

            // ── Load a as (a1:a0) where a = a1*2^256 + a0, a1 <= 128 bits ──
            let a0 := 0
            let a1 := 0
            switch eq(mload(a), 48)
            case 1 {
                // Fast path: canonical 48-byte element
                a1 := shr(128, mload(add(a, 0x20)))
                a0 := mload(add(a, 0x30))
            }
            default {
                let len := mload(a)
                if gt(len, 31) {
                    a0 := mload(add(a, add(0x20, sub(len, 32))))
                    let hb := sub(len, 32)
                    if gt(hb, 0) { a1 := shr(mul(sub(32, hb), 8), mload(add(a, 0x20))) }
                }
                if and(gt(len, 0), lt(len, 32)) { a0 := shr(mul(sub(32, len), 8), mload(add(a, 0x20))) }
                if eq(len, 32) { a0 := mload(add(a, 0x20)) }
            }

            // ── Squaring: product = (r2:r1:r0) using 3 partial products ──
            // a0*a0 -> (hi0:lo0)
            let lo0 := mul(a0, a0)
            let mm0 := mulmod(a0, a0, not(0))
            let hi0 := sub(sub(mm0, lo0), lt(mm0, lo0))

            // a1*a0 -> (hi1:lo1), then double it
            let lo1 := mul(a1, a0)
            let mm1 := mulmod(a1, a0, not(0))
            let hi1 := sub(sub(mm1, lo1), lt(mm1, lo1))
            // Double: (hi1:lo1) << 1
            hi1 := or(shl(1, hi1), shr(255, lo1))
            lo1 := shl(1, lo1)

            // a1*a1 -> fits in 256 bits since a1 <= 128 bits
            let mid_top := mul(a1, a1)

            // Accumulate into (r2:r1:r0)
            let r0 := lo0
            // r1 = hi0 + lo1
            let r1 := add(hi0, lo1)
            // r2 = hi1 + mid_top + carry
            let r2 := add(add(hi1, mid_top), lt(r1, hi0))

            // ── Barrett reduction mod p (fixed modulus) ──
            // NOTE: deliberately duplicated between mul and sqr (keep in sync).
            // A shared helper measured ~7% slower end-to-end: via-ir does not
            // reliably inline it inside large callers like Fp2.mul.
            // mu = floor(2^1024 / p) = (M2:M1:M0), precomputed.
            // q = ((x >> 256) * mu) >> 768 where x = (r2:r1:r0) < p^2.
            // Then r = x - q*p, with r < 3p (at most 2 corrective subtractions;
            // r fits in 512 bits so only the low 2 limbs of q*p are needed).
            let Q0
            let Q1
            {
                let M0 := 0xad397b918f6ff20d533b6c08511c60e2757079ace6bd401859778ceb4dabc4f8
                let M1 := 0x1b82741ff6a0a94bdf4771e0286779d3997167a058f1c07b13e207f56591ba2e
                let M2 := 0x9d835d2f3cc9e45ce28101b0cc7a6ba29

                // Six 256x256->512 partial products of (r1, r2) x (M0, M1, M2)
                let lo00 := mul(r1, M0)
                let mm := mulmod(r1, M0, not(0))
                let hi00 := sub(sub(mm, lo00), lt(mm, lo00))

                let lo01 := mul(r1, M1)
                mm := mulmod(r1, M1, not(0))
                let hi01 := sub(sub(mm, lo01), lt(mm, lo01))

                let lo02 := mul(r1, M2)
                mm := mulmod(r1, M2, not(0))
                let hi02 := sub(sub(mm, lo02), lt(mm, lo02))

                let lo10 := mul(r2, M0)
                mm := mulmod(r2, M0, not(0))
                let hi10 := sub(sub(mm, lo10), lt(mm, lo10))

                let lo11 := mul(r2, M1)
                mm := mulmod(r2, M1, not(0))
                let hi11 := sub(sub(mm, lo11), lt(mm, lo11))

                let lo12 := mul(r2, M2)
                mm := mulmod(r2, M2, not(0))
                let hi12 := sub(sub(mm, lo12), lt(mm, lo12))

                // Product limb 1 = hi00 + lo01 + lo10 (value discarded, carry kept)
                let L := add(hi00, lo01)
                let cA := lt(L, hi00)
                L := add(L, lo10)
                cA := add(cA, lt(L, lo10))

                // Product limb 2 = hi01 + hi10 + lo02 + lo11 + cA (value discarded, carry kept)
                L := add(hi01, hi10)
                let cB := lt(L, hi01)
                L := add(L, lo02)
                cB := add(cB, lt(L, lo02))
                L := add(L, lo11)
                cB := add(cB, lt(L, lo11))
                L := add(L, cA)
                cB := add(cB, lt(L, cA))

                // Product limb 3 = hi02 + hi11 + lo12 + cB -> Q0 (low limb of q)
                Q0 := add(hi02, hi11)
                let cC := lt(Q0, hi02)
                Q0 := add(Q0, lo12)
                cC := add(cC, lt(Q0, lo12))
                Q0 := add(Q0, cB)
                cC := add(cC, lt(Q0, cB))

                // Product limb 4 -> Q1 (high limb of q)
                Q1 := add(hi12, cC)
            }

            let p1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let p0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // r = x - q*p, exact in 512 bits -> only low 2 limbs of q*p needed
            let rem0
            let rem1
            {
                let lo := mul(Q0, p0)
                let mm := mulmod(Q0, p0, not(0))
                let hi := sub(sub(mm, lo), lt(mm, lo))
                // low-2-limb product: B0 = lo, B1 = hi + lo(Q0*p1) + lo(Q1*p0) mod 2^256
                let B1 := add(add(hi, mul(Q0, p1)), mul(Q1, p0))

                rem0 := sub(r0, lo)
                rem1 := sub(sub(r1, B1), lt(r0, lo))
            }

            // Correct: subtract p while rem >= p (at most twice by the Barrett bound)
            if or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0)))) {
                let nr := sub(rem0, p0)
                rem1 := sub(sub(rem1, p1), gt(p0, rem0))
                rem0 := nr
            }
            if or(gt(rem1, p1), and(eq(rem1, p1), iszero(lt(rem0, p0)))) {
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

    /// @notice Copy the value of src into the pre-allocated buffer dst.
    /// @dev Used to park live values in a staging area so loop garbage can be
    ///      reclaimed by resetting the free memory pointer. dst must have been
    ///      allocated with at least src.length bytes of capacity (all Fp
    ///      elements in this codebase are 48 bytes).
    function copyInto(bytes memory src, bytes memory dst) internal pure {
        assembly {
            // Constant-size copy: length word + 48 data bytes. Elements shorter
            // than 48 bytes keep correct semantics (their length word is copied
            // too); the over-read past a short src is harmless in EVM memory.
            mcopy(dst, src, 0x50)
        }
    }

    /// @notice Allocate the 3-buffer staging area for the park/rewind
    ///         memory-recycling pattern (see park3).
    function stage3() internal pure returns (bytes[3] memory stage) {
        stage[0] = new bytes(48);
        stage[1] = new bytes(48);
        stage[2] = new bytes(48);
    }

    /// @notice Park (x, y, z) in the staging buffers and rewind the free memory
    ///         pointer to memBase, reclaiming a loop iteration's garbage.
    /// @dev memBase must have been captured AFTER `stage` was allocated, and the
    ///      returned staged values must replace the caller's locals — the old
    ///      pointers dangle once the pointer is rewound.
    function park3(
        bytes[3] memory stage,
        bytes memory x,
        bytes memory y,
        bytes memory z,
        uint256 memBase
    ) internal pure returns (bytes memory, bytes memory, bytes memory) {
        copyInto(x, stage[0]);
        copyInto(y, stage[1]);
        copyInto(z, stage[2]);
        assembly { mstore(0x40, memBase) }
        return (stage[0], stage[1], stage[2]);
    }

    /// @notice Encode a uint256 as a 48-byte big-endian field element.
    function fromUint256(uint256 x) internal pure returns (bytes memory) {
        return _pack(0, x);
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

    /// @dev Specialized 2-limb Montgomery exponentiation for the BLS12-381 base field.
    ///      base^exponent mod p, where p is the BLS12-381 base field modulus.
    function _modexp(bytes memory base, bytes memory exponent) private pure returns (bytes memory result) {
        // Load base as 2 limbs (little-endian): (a0, a1)
        (uint256 a1, uint256 a0) = _loadFp(base);
        assembly {
            // Allocate the 48-byte result inline; every byte is overwritten below,
            // so new bytes' zero-initialization is skipped.
            result := mload(0x40)
            mstore(0x40, add(result, 0x50))
            mstore(result, 48)

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
                    let mm := mulmod(x0, y0, not(0))
                    let hi := sub(sub(mm, lo), lt(mm, lo))
                    t0 := lo
                    let carry := hi

                    lo := mul(x0, y1)
                    mm := mulmod(x0, y1, not(0))
                    hi := sub(sub(mm, lo), lt(mm, lo))
                    let s := add(lo, carry)
                    t1 := s
                    t2 := add(hi, lt(s, lo))
                }

                // Reduce
                let m := mul(t0, 0x19ecca0e8eb2db4c16ef2ef0c8e30b48286adb92d9d113e889f3fffcfffcfffd)
                {
                    let _n0 := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                    let lo := mul(m, _n0)
                    let mm := mulmod(m, _n0, not(0))
                    let hi := sub(sub(mm, lo), lt(mm, lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))

                    let _n1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                    lo := mul(m, _n1)
                    mm := mulmod(m, _n1, not(0))
                    hi := sub(sub(mm, lo), lt(mm, lo))
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
                    let mm := mulmod(x1, y0, not(0))
                    let hi := sub(sub(mm, lo), lt(mm, lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))
                    t0 := s

                    lo := mul(x1, y1)
                    mm := mulmod(x1, y1, not(0))
                    hi := sub(sub(mm, lo), lt(mm, lo))
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
                    let mm := mulmod(m, _n0, not(0))
                    let hi := sub(sub(mm, lo), lt(mm, lo))
                    let s := add(t0, lo)
                    let carry := add(hi, lt(s, t0))

                    let _n1 := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                    lo := mul(m, _n1)
                    mm := mulmod(m, _n1, not(0))
                    hi := sub(sub(mm, lo), lt(mm, lo))
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
