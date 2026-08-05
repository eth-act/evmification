// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LimbMath} from "./LimbMath.sol";

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
        if (LimbMath.isZeroBytes(modulus) || LimbMath.isOneBytes(modulus)) return result;

        uint256 k = (modLen + 31) / 32; // number of 256-bit limbs

        // Single-limb modulus: native mulmod square-and-multiply, no limb machinery
        if (k == 1) {
            LimbMath.modexpWordInto(base, exponent, modulus, result);
            return result;
        }

        // Convert inputs to little-endian limb arrays
        uint256[] memory n = LimbMath.bytesToLimbs(modulus, k);

        // Check exponent early — small exponents skip Montgomery setup entirely
        uint256 expSmall = _exponentToUint(exponent);
        uint256[] memory res;

        if (expSmall == 1) {
            // e = 1: result is just base mod n
            res = _reduceBase(base, n, k);
        } else if (expSmall == 3) {
            // e = 3: direct schoolbook multiply, no Montgomery overhead
            uint256[] memory a = _reduceBase(base, n, k);
            // base² mod n
            uint256[] memory a2 = LimbMath.schoolbookRem(
                LimbMath.schoolbookMul(a, k, a, k), 2 * k, n, k
            );
            // base³ = base² × base mod n
            res = LimbMath.schoolbookRem(
                LimbMath.schoolbookMul(a2, k, a, k), 2 * k, n, k
            );
        } else {
            // Montgomery path — worth the setup cost for larger exponents
            uint256 n0inv = _computeN0inv(n[0]);
            uint256[] memory one = new uint256[](k);
            one[0] = 1;
            // Straight to the Montgomery domain: one division replaces the
            // separate base reduction, R² mod n, and the montMul by R².
            uint256[] memory aM = _toMontgomery(base, n, k);

            if (expSmall == 65537) {
                uint256[] memory rM = _fastExp65537(aM, n, n0inv, k);
                res = _montMul(rM, one, n, n0inv, k);
            } else {
                // rM starts at R mod n, the Montgomery form of 1
                uint256[] memory rM = _rModN(n, k);
                rM = _modexpLoop(rM, aM, exponent, n, n0inv, k);
                res = _montMul(rM, one, n, n0inv, k);
            }
        }

        LimbMath.limbsToBytes(res, result, modLen);
    }

    /// @dev base mod n as k little-endian limbs. Skips the division when the
    ///      base already fits in k limbs and is smaller than n.
    function _reduceBase(bytes memory base, uint256[] memory n, uint256 k)
        private pure returns (uint256[] memory)
    {
        if ((base.length + 31) / 32 <= k) {
            uint256[] memory baseLimbs = LimbMath.bytesToLimbs(base, k);
            if (_limbsLt(baseLimbs, n, k)) return baseLimbs;
            return LimbMath.schoolbookRem(baseLimbs, k, n, k);
        }
        return LimbMath.reduceBase(base, n, k);
    }

    // ── Montgomery setup ──────────────────────────────────────────────

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

    /// @dev Computes base·R mod n where R = 2^{256k} — the Montgomery form of
    ///      base — by reducing base shifted up k limbs.
    ///
    ///      The textbook route is montMul(base mod n, R² mod n), which costs a
    ///      division for R², a division to reduce the base, and a montMul. The
    ///      shift is free (the low k limbs of the dividend are just zero), so
    ///      one division does the whole job.
    function _toMontgomery(bytes memory base, uint256[] memory n, uint256 k)
        private pure returns (uint256[] memory)
    {
        uint256 baseK = (base.length + 31) / 32;
        if (baseK == 0) return new uint256[](k);

        uint256 dLen = baseK + k;
        uint256[] memory dividend = new uint256[](dLen); // zero-initialised
        uint256[] memory baseLimbs = LimbMath.bytesToLimbs(base, baseK);
        assembly {
            mcopy(
                add(add(dividend, 0x20), shl(5, k)),
                add(baseLimbs, 0x20),
                shl(5, baseK)
            )
        }
        return LimbMath.schoolbookRem(dividend, dLen, n, k);
    }

    /// @dev Computes R mod n where R = 2^{256k} — the Montgomery form of 1.
    ///      Only two quotient limbs, so this is far cheaper than the montMul by
    ///      R² it replaces.
    function _rModN(uint256[] memory n, uint256 k)
        private pure returns (uint256[] memory)
    {
        uint256[] memory dividend = new uint256[](k + 1);
        dividend[k] = 1;
        return LimbMath.schoolbookRem(dividend, k + 1, n, k);
    }

    /// @dev Montgomery squaring. SOS trades multiplies for three extra O(k)
    ///      passes (zero, double, diagonal); below k = 9 those passes cost more
    ///      than the multiplies they save, so CIOS wins outright.
    function _sqr(uint256[] memory x, uint256[] memory n, uint256 n0inv, uint256 k)
        private pure returns (uint256[] memory)
    {
        if (k < 9) return _montMul(x, x, n, n0inv, k);
        return _montSqr(x, n, n0inv, k);
    }

    /// @dev Returns true if a < b (both k-limb little-endian arrays).
    function _limbsLt(uint256[] memory a, uint256[] memory b, uint256 k)
        private pure returns (bool)
    {
        for (uint256 i = k; i > 0;) {
            unchecked { i--; }
            if (a[i] < b[i]) return true;
            if (a[i] > b[i]) return false;
        }
        return false; // equal
    }

    // ── Square-and-multiply ───────────────────────────────────────────

    /// @dev Left-to-right binary exponentiation in the Montgomery domain.
    ///      Recycles temporary memory each iteration to avoid MemoryOOG on large exponents.
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

        // Save free memory pointer; all temporaries from _montMul will be
        // allocated above this mark and reclaimed each iteration.
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }

        // Find the topmost set bit in the first non-zero byte
        uint256 topBit = 7;
        {
            uint256 first = uint8(exponent[startByte]);
            while (topBit > 0 && (first >> topBit) & 1 == 0) {
                topBit--;
            }
        }

        // Unified square-and-multiply loop across all exponent bytes.
        // topBit is the first byte's top set bit, then 7 for all later bytes.
        for (uint256 byteIdx = startByte; byteIdx < expLen; byteIdx++) {
            uint256 b = uint8(exponent[byteIdx]);
            uint256 bit = topBit + 1;
            topBit = 7;
            for (; bit > 0;) {
                unchecked { bit--; }
                assembly { mstore(0x40, freeMemBase) }
                LimbMath.copyLimbs(_sqr(rM, n, n0inv, k), rM, k); // square
                if ((b >> bit) & 1 == 1) {
                    assembly { mstore(0x40, freeMemBase) }
                    LimbMath.copyLimbs(_montMul(rM, aM, n, n0inv, k), rM, k); // multiply
                }
            }
        }

        return rM;
    }

    // ── Fast-path exponentiation for common RSA exponents ─────────────

    /// @dev Extracts exponent as uint256 (stripping leading zeros), or returns 0 if > 32 significant bytes.
    function _exponentToUint(bytes memory exponent) private pure returns (uint256 v) {
        uint256 len = exponent.length;
        if (len == 0) return 0;
        // Skip leading zero bytes
        uint256 start = 0;
        while (start < len && exponent[start] == 0) {
            start++;
        }
        uint256 sigLen = len - start;
        if (sigLen == 0 || sigLen > 32) return 0;
        assembly {
            v := shr(mul(sub(32, sigLen), 8), mload(add(add(exponent, 0x20), start)))
        }
    }

    /// @dev b^65537 in Montgomery domain. e = 2^16 + 1: square 16 times, multiply once.
    function _fastExp65537(
        uint256[] memory aM,
        uint256[] memory n,
        uint256 n0inv,
        uint256 k
    ) private pure returns (uint256[] memory rM) {
        rM = new uint256[](k);
        LimbMath.copyLimbs(aM, rM, k);
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }
        for (uint256 i = 0; i < 16; i++) {
            assembly { mstore(0x40, freeMemBase) }
            LimbMath.copyLimbs(_sqr(rM, n, n0inv, k), rM, k);
        }
        assembly { mstore(0x40, freeMemBase) }
        LimbMath.copyLimbs(_montMul(rM, aM, n, n0inv, k), rM, k);
    }


    // ── Montgomery squaring (SOS) ───────────────────────────────────

    /// @dev Computes a² * R⁻¹ mod n using Separated Operand Scanning.
    ///      Exploits a*a symmetry: upper triangle + double + diagonal = half the multiplies.
    ///
    ///      The two O(k²) passes are unrolled 4x. Constant sub-offsets
    ///      (0x20/0x40/0x60) from one base pointer keep the per-limb pointers off
    ///      the stack and amortise the loop control over four limbs; rolled, more
    ///      than half the gas in these loops went to DUP/SWAP chains. The
    ///      `k mod 4` remainder falls through to a single-step tail loop.
    function _montSqr(
        uint256[] memory a,
        uint256[] memory n,
        uint256 n0inv,
        uint256 k
    ) private pure returns (uint256[] memory res) {
        res = new uint256[](k);

        assembly {
            let aP := add(a, 0x20)
            let nP := add(n, 0x20)
            let resP := add(res, 0x20)
            let kWords := shl(5, k)
            let aEnd := add(aP, kWords)

            // Allocate and zero scratch s[0..2k] (2k+1 words)
            let sP := mload(0x40)
            let sEnd := add(sP, add(shl(1, kWords), 0x20))
            mstore(0x40, sEnd)
            for { let p := sP } lt(p, sEnd) { p := add(p, 0x20) } {
                mstore(p, 0)
            }

            // ── Step 1a: Off-diagonal (upper triangle) ──
            // For i < j: accumulate a[i]*a[j] into s[i+j]
            {
                // sRow tracks &s[2i+1]; advances 2 words per row
                let sRow := add(sP, 0x20)
                for { let aOff_i := aP } lt(aOff_i, aEnd) { aOff_i := add(aOff_i, 0x20) } {
                    let ai := mload(aOff_i)
                    let carry := 0
                    let sOff := sRow
                    let aOff_j := add(aOff_i, 0x20)

                    // Rows shrink by one limb as i advances, so the 4x bound is
                    // recomputed per row.
                    let aMain := add(aOff_j, and(sub(aEnd, aOff_j), not(0x7f)))
                    for {} lt(aOff_j, aMain) {
                        aOff_j := add(aOff_j, 0x80)
                        sOff := add(sOff, 0x80)
                    } {
                        {
                            let aj := mload(aOff_j)
                            let lo := mul(ai, aj)
                            let mmr := mulmod(ai, aj, not(0))
                            let s1 := add(lo, mload(sOff))
                            let s2 := add(s1, carry)
                            mstore(sOff, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x20)
                            let aj := mload(add(aOff_j, 0x20))
                            let lo := mul(ai, aj)
                            let mmr := mulmod(ai, aj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x40)
                            let aj := mload(add(aOff_j, 0x40))
                            let lo := mul(ai, aj)
                            let mmr := mulmod(ai, aj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x60)
                            let aj := mload(add(aOff_j, 0x60))
                            let lo := mul(ai, aj)
                            let mmr := mulmod(ai, aj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                    }

                    for {} lt(aOff_j, aEnd) {
                        aOff_j := add(aOff_j, 0x20)
                        sOff := add(sOff, 0x20)
                    } {
                        let aj := mload(aOff_j)
                        let lo := mul(ai, aj)
                        let mmr := mulmod(ai, aj, not(0))
                        let s1 := add(lo, mload(sOff))
                        let s2 := add(s1, carry)
                        mstore(sOff, s2)
                        carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                    }
                    mstore(sOff, carry)

                    sRow := add(sRow, 0x40)
                }
            }

            // ── Step 1b: Double (left shift by 1 bit) ──
            {
                let carry := 0
                for { let sOff := sP } lt(sOff, sEnd) { sOff := add(sOff, 0x20) } {
                    let val := mload(sOff)
                    mstore(sOff, or(shl(1, val), carry))
                    carry := shr(255, val)
                }
            }

            // ── Step 1c: Add diagonal a[i]² into s[2i..2i+1] ──
            {
                let sOff := sP
                for { let aOff := aP } lt(aOff, aEnd) { aOff := add(aOff, 0x20) } {
                    let ai := mload(aOff)

                    let lo := mul(ai, ai)
                    let mmr := mulmod(ai, ai, not(0))
                    let hi := sub(sub(mmr, lo), lt(mmr, lo))

                    let s2i := mload(sOff)
                    let sum1 := add(s2i, lo)
                    let c1 := lt(sum1, s2i)
                    mstore(sOff, sum1)

                    let sOff1 := add(sOff, 0x20)
                    let s2i1 := mload(sOff1)
                    let sum2 := add(s2i1, hi)
                    let c2 := lt(sum2, s2i1)
                    let sum3 := add(sum2, c1)
                    let c3 := lt(sum3, sum2)
                    mstore(sOff1, sum3)

                    // Propagate carry
                    let carry := add(c2, c3)
                    let propOff := add(sOff1, 0x20)
                    for {} gt(carry, 0) {} {
                        let val := mload(propOff)
                        let newVal := add(val, carry)
                        carry := lt(newVal, val)
                        mstore(propOff, newVal)
                        propOff := add(propOff, 0x20)
                    }

                    sOff := add(sOff, 0x40)
                }
            }

            // ── Step 2: Montgomery reduction (no shift, advance base) ──
            {
                let nEnd := add(nP, kWords)
                let sKEnd := add(sP, kWords)
                let nMain := add(nP, and(kWords, not(0x7f)))
                let sBase := sP
                for {} lt(sBase, sKEnd) { sBase := add(sBase, 0x20) } {
                    let m := mul(mload(sBase), n0inv)
                    let carry := 0
                    let sOff := sBase
                    let nOff := nP

                    // j = 0 stores the (provably zero) low limb back into s[base],
                    // which is never read again, so all k limbs share one path.
                    for {} lt(nOff, nMain) {
                        nOff := add(nOff, 0x80)
                        sOff := add(sOff, 0x80)
                    } {
                        {
                            let nj := mload(nOff)
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(sOff))
                            let s2 := add(s1, carry)
                            mstore(sOff, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x20)
                            let nj := mload(add(nOff, 0x20))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x40)
                            let nj := mload(add(nOff, 0x40))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let sA := add(sOff, 0x60)
                            let nj := mload(add(nOff, 0x60))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(sA))
                            let s2 := add(s1, carry)
                            mstore(sA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                    }

                    for {} lt(nOff, nEnd) {
                        nOff := add(nOff, 0x20)
                        sOff := add(sOff, 0x20)
                    } {
                        let nj := mload(nOff)
                        let lo := mul(m, nj)
                        let mmr := mulmod(m, nj, not(0))
                        let s1 := add(lo, mload(sOff))
                        let s2 := add(s1, carry)
                        mstore(sOff, s2)
                        carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                    }

                    // Propagate carry into s[base+k..2k]
                    for {} gt(carry, 0) {} {
                        let val := mload(sOff)
                        let newVal := add(val, carry)
                        carry := lt(newVal, val)
                        mstore(sOff, newVal)
                        sOff := add(sOff, 0x20)
                    }
                }

                // ── Final conditional subtraction ──
                // Result is in s[k..2k-1], sBase points to s[k]
                {
                    let doSub := gt(mload(add(sBase, kWords)), 0)

                    if iszero(doSub) {
                        doSub := 1
                        let nOff := add(nP, kWords)
                        for { let sOff := add(sBase, kWords) } gt(sOff, sBase) {} {
                            sOff := sub(sOff, 0x20)
                            nOff := sub(nOff, 0x20)
                            let sL := mload(sOff)
                            let nL := mload(nOff)
                            if gt(sL, nL) { sOff := sBase }
                            if lt(sL, nL) { doSub := 0 sOff := sBase }
                        }
                    }

                    mcopy(resP, sBase, kWords)

                    if doSub {
                        let borrow := 0
                        let rOff := resP
                        let nOff := nP
                        let rEnd := add(resP, kWords)
                        for {} lt(rOff, rEnd) {} {
                            let rL := mload(rOff)
                            let nL := mload(nOff)
                            let d := sub(rL, nL)
                            let nb := lt(rL, nL)
                            let d2 := sub(d, borrow)
                            borrow := or(nb, lt(d, borrow))
                            mstore(rOff, d2)
                            rOff := add(rOff, 0x20)
                            nOff := add(nOff, 0x20)
                        }
                    }
                }
            }
        }
    }

    // ── Montgomery multiplication (CIOS) ──────────────────────────────

    /// @dev Computes a * b * R^{-1} mod n using CIOS (Coarsely Integrated Operand Scanning).
    ///      Both O(k²) passes are unrolled 4x; see `_montSqr` for why.
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
            let kW := shl(5, k)

            // Allocate scratch [scrap][t[0..k+1]]. The scrap word below t[0]
            // absorbs the reduce pass's discarded low limb, which lets that pass
            // run uniformly over all k limbs instead of peeling j = 0.
            let tP := add(mload(0x40), 0x20)
            let tEnd := add(tP, kW) // &t[k]
            mstore(0x40, add(tEnd, 0x40))

            // Zero t
            for { let p := tP } lt(p, add(tEnd, 0x40)) { p := add(p, 0x20) } {
                mstore(p, 0)
            }

            // Bound of the 4-limb-at-a-time section; the remainder (k mod 4
            // limbs) is handled by the single-step tail loops.
            let tMain := add(tP, and(kW, not(0x7f)))

            // Main CIOS loop: one iteration per limb of a
            let aEnd := add(aP, kW)
            for { let aOff := aP } lt(aOff, aEnd) { aOff := add(aOff, 0x20) } {
                let ai := mload(aOff)

                // Step 1: Multiply pass — t += a[i] * b
                {
                    let carry := 0
                    let bOff := bP
                    let tOff := tP

                    for {} lt(tOff, tMain) {
                        tOff := add(tOff, 0x80)
                        bOff := add(bOff, 0x80)
                    } {
                        {
                            let bj := mload(bOff)
                            let lo := mul(ai, bj)
                            let mmr := mulmod(ai, bj, not(0))
                            let s1 := add(lo, mload(tOff))
                            let s2 := add(s1, carry)
                            mstore(tOff, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x20)
                            let bj := mload(add(bOff, 0x20))
                            let lo := mul(ai, bj)
                            let mmr := mulmod(ai, bj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(tA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x40)
                            let bj := mload(add(bOff, 0x40))
                            let lo := mul(ai, bj)
                            let mmr := mulmod(ai, bj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(tA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x60)
                            let bj := mload(add(bOff, 0x60))
                            let lo := mul(ai, bj)
                            let mmr := mulmod(ai, bj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(tA, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                    }

                    // Tail: k mod 4 limbs
                    for {} lt(tOff, tEnd) {
                        tOff := add(tOff, 0x20)
                        bOff := add(bOff, 0x20)
                    } {
                        let bj := mload(bOff)
                        let lo := mul(ai, bj)
                        let mmr := mulmod(ai, bj, not(0))
                        let s1 := add(lo, mload(tOff))
                        let s2 := add(s1, carry)
                        mstore(tOff, s2)
                        carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                    }

                    // Propagate carry into t[k] and t[k+1]
                    let tk := mload(tEnd)
                    let tkNew := add(tk, carry)
                    mstore(tEnd, tkNew)
                    let tk1Off := add(tEnd, 0x20)
                    mstore(tk1Off, add(mload(tk1Off), lt(tkNew, tk)))
                }

                // Step 2: Reduce pass — m = t[0]*n0inv; t += m*n; shift right one word
                {
                    let m := mul(mload(tP), n0inv)
                    let carry := 0
                    let nOff := nP
                    let tOff := tP

                    // j = 0 writes the (provably zero) low limb into the scrap
                    // word at tP - 0x20, so every limb takes the same path.
                    for {} lt(tOff, tMain) {
                        tOff := add(tOff, 0x80)
                        nOff := add(nOff, 0x80)
                    } {
                        {
                            let nj := mload(nOff)
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(tOff))
                            let s2 := add(s1, carry)
                            mstore(sub(tOff, 0x20), s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x20)
                            let nj := mload(add(nOff, 0x20))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(tOff, s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x40)
                            let nj := mload(add(nOff, 0x40))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(add(tOff, 0x20), s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                        {
                            let tA := add(tOff, 0x60)
                            let nj := mload(add(nOff, 0x60))
                            let lo := mul(m, nj)
                            let mmr := mulmod(m, nj, not(0))
                            let s1 := add(lo, mload(tA))
                            let s2 := add(s1, carry)
                            mstore(add(tOff, 0x40), s2)
                            carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                        }
                    }

                    // Tail: k mod 4 limbs
                    for {} lt(tOff, tEnd) {
                        tOff := add(tOff, 0x20)
                        nOff := add(nOff, 0x20)
                    } {
                        let nj := mload(nOff)
                        let lo := mul(m, nj)
                        let mmr := mulmod(m, nj, not(0))
                        let s1 := add(lo, mload(tOff))
                        let s2 := add(s1, carry)
                        mstore(sub(tOff, 0x20), s2)
                        carry := add(sub(sub(mmr, lo), lt(mmr, lo)), add(lt(s1, lo), lt(s2, s1)))
                    }

                    // Propagate carry into upper limbs (with shift)
                    let tkVal := mload(tEnd)
                    let sum := add(tkVal, carry)
                    mstore(sub(tEnd, 0x20), sum)
                    let tk1Off := add(tEnd, 0x20)
                    mstore(tEnd, add(mload(tk1Off), lt(sum, tkVal)))
                    mstore(tk1Off, 0)
                }
            }

            // Final conditional subtraction: if t >= n then t -= n
            {
                let doSub := gt(mload(tEnd), 0)

                if iszero(doSub) {
                    // Compare t vs n from the most significant limb downward
                    doSub := 1 // assume t >= n (covers the equal case)
                    let nOff := add(nP, kW)
                    for { let tOff := tEnd } gt(tOff, tP) {} {
                        tOff := sub(tOff, 0x20)
                        nOff := sub(nOff, 0x20)
                        let tL := mload(tOff)
                        let nL := mload(nOff)
                        if gt(tL, nL) { tOff := tP }             // t > n, subtract
                        if lt(tL, nL) { doSub := 0 tOff := tP }  // t < n, no subtract
                        // if equal, continue to next limb
                    }
                }

                // Copy t[0..k-1] to res
                mcopy(resP, tP, kW)

                // Conditionally subtract n
                if doSub {
                    let borrow := 0
                    let nOff := nP
                    let rEnd := add(resP, kW)
                    for { let rOff := resP } lt(rOff, rEnd) {
                        rOff := add(rOff, 0x20)
                        nOff := add(nOff, 0x20)
                    } {
                        let rL := mload(rOff)
                        let nL := mload(nOff)
                        let d := sub(rL, nL)
                        let nb := lt(rL, nL)
                        let d2 := sub(d, borrow)
                        borrow := or(nb, lt(d, borrow))
                        mstore(rOff, d2)
                    }
                }
            }
        }
    }
}
