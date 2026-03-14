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

        // Convert inputs to little-endian limb arrays
        uint256[] memory n = LimbMath.bytesToLimbs(modulus, k);

        // Fast path: skip schoolbook division when base already fits and base < n
        uint256[] memory a;
        {
            uint256 baseLen = base.length;
            uint256 baseK = (baseLen + 31) / 32;
            if (baseK <= k) {
                uint256[] memory baseLimbs = LimbMath.bytesToLimbs(base, k);
                if (_limbsLt(baseLimbs, n, k)) {
                    a = baseLimbs;
                } else {
                    a = LimbMath.schoolbookRem(baseLimbs, k, n, k);
                }
            } else {
                a = LimbMath.reduceBase(base, n, k);
            }
        }

        // Montgomery constants
        uint256 n0inv = _computeN0inv(n[0]);
        uint256[] memory r2 = _computeR2ModN(k, n);

        // one = 1 as a k-limb number
        uint256[] memory one = new uint256[](k);
        one[0] = 1;

        // Convert base to Montgomery domain
        uint256[] memory aM = _montMul(a, r2, n, n0inv, k);

        // Fast paths for common RSA exponents (skip generic loop + rM setup)
        uint256 expSmall = _exponentToUint(exponent);
        uint256[] memory res;
        if (expSmall == 65537) {
            // e = 2^16 + 1: square 16 times, then multiply by base
            uint256[] memory rM = _fastExp65537(aM, n, n0inv, k);
            res = _montMul(rM, one, n, n0inv, k);
        } else if (expSmall == 3 || expSmall == 1) {
            // e = 3: square once, multiply by base; e = 1: identity
            uint256[] memory rM = expSmall == 3 ? _fastExp3(aM, n, n0inv, k) : aM;
            res = _montMul(rM, one, n, n0inv, k);
        } else {
            // Generic path
            uint256[] memory rM = _montMul(one, r2, n, n0inv, k);
            rM = _modexpLoop(rM, aM, exponent, n, n0inv, k);
            res = _montMul(rM, one, n, n0inv, k);
        }

        LimbMath.limbsToBytes(res, result, modLen);
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

    /// @dev Computes R^2 mod n where R = 2^{256k}.
    function _computeR2ModN(uint256 k, uint256[] memory n)
        private pure returns (uint256[] memory)
    {
        uint256 dLen = 2 * k + 1;
        uint256[] memory dividend = new uint256[](dLen);
        dividend[2 * k] = 1;
        return LimbMath.schoolbookRem(dividend, dLen, n, k);
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
        uint8 b = uint8(exponent[startByte]);
        uint256 topBit = 7;
        while (topBit > 0 && (b >> topBit) & 1 == 0) {
            topBit--;
        }

        // Process first non-zero byte (from topBit down to bit 0)
        for (uint256 bit = topBit;;) {
            assembly { mstore(0x40, freeMemBase) }
            LimbMath.copyLimbs(_montSqr(rM, n, n0inv, k), rM, k); // square
            if ((b >> bit) & 1 == 1) {
                assembly { mstore(0x40, freeMemBase) }
                LimbMath.copyLimbs(_montMul(rM, aM, n, n0inv, k), rM, k); // multiply
            }
            if (bit == 0) break;
            unchecked { bit--; }
        }

        // Process remaining exponent bytes (all 8 bits each)
        for (uint256 byteIdx = startByte + 1; byteIdx < expLen; byteIdx++) {
            b = uint8(exponent[byteIdx]);
            for (uint256 bit = 8; bit > 0;) {
                unchecked { bit--; }
                assembly { mstore(0x40, freeMemBase) }
                LimbMath.copyLimbs(_montSqr(rM, n, n0inv, k), rM, k); // square
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
            LimbMath.copyLimbs(_montSqr(rM, n, n0inv, k), rM, k);
        }
        assembly { mstore(0x40, freeMemBase) }
        LimbMath.copyLimbs(_montMul(rM, aM, n, n0inv, k), rM, k);
    }

    /// @dev b^3 in Montgomery domain. e = 2 + 1: square once, multiply once.
    function _fastExp3(
        uint256[] memory aM,
        uint256[] memory n,
        uint256 n0inv,
        uint256 k
    ) private pure returns (uint256[] memory rM) {
        rM = new uint256[](k);
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }
        LimbMath.copyLimbs(_montSqr(aM, n, n0inv, k), rM, k);
        assembly { mstore(0x40, freeMemBase) }
        LimbMath.copyLimbs(_montMul(rM, aM, n, n0inv, k), rM, k);
    }

    // ── Montgomery squaring (SOS) ───────────────────────────────────

    /// @dev Computes a² * R⁻¹ mod n using Separated Operand Scanning.
    ///      Exploits a*a symmetry: upper triangle + double + diagonal = half the multiplies.
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
            let kWords := mul(k, 0x20)
            let k2p1 := add(mul(k, 2), 1)

            // Allocate and zero scratch s[0..2k] (2k+1 words)
            let sP := mload(0x40)
            let sEnd := add(sP, mul(k2p1, 0x20))
            mstore(0x40, sEnd)
            for { let p := sP } lt(p, sEnd) { p := add(p, 0x20) } {
                mstore(p, 0)
            }

            // ── Step 1a: Off-diagonal (upper triangle) ──
            // For i < j: accumulate a[i]*a[j] into s[i+j]
            {
                let aOff_i := aP
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                    let ai := mload(aOff_i)
                    let carry := 0
                    let aOff_j := add(aOff_i, 0x20)
                    let sOff := add(sP, mul(add(mul(2, i), 1), 0x20))

                    for { let j := add(i, 1) } lt(j, k) { j := add(j, 1) } {
                        let aj := mload(aOff_j)

                        let lo := mul(ai, aj)
                        let mmr := mulmod(ai, aj, not(0))
                        let hi := sub(sub(mmr, lo), lt(mmr, lo))

                        let s1 := add(lo, mload(sOff))
                        let c1 := lt(s1, lo)
                        let s2 := add(s1, carry)
                        mstore(sOff, s2)
                        carry := add(hi, add(c1, lt(s2, s1)))

                        sOff := add(sOff, 0x20)
                        aOff_j := add(aOff_j, 0x20)
                    }
                    mstore(sOff, carry)

                    aOff_i := add(aOff_i, 0x20)
                }
            }

            // ── Step 1b: Double (left shift by 1 bit) ──
            {
                let carry := 0
                let sOff := sP
                for { let i := 0 } lt(i, k2p1) { i := add(i, 1) } {
                    let val := mload(sOff)
                    mstore(sOff, or(shl(1, val), carry))
                    carry := shr(255, val)
                    sOff := add(sOff, 0x20)
                }
            }

            // ── Step 1c: Add diagonal a[i]² into s[2i..2i+1] ──
            {
                let aOff := aP
                let sOff := sP
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
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
                    aOff := add(aOff, 0x20)
                }
            }

            // ── Step 2: Montgomery reduction (no shift, advance base) ──
            {
                let sBase := sP
                for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                    let m := mul(mload(sBase), n0inv)
                    let carry := 0
                    let sOff := sBase
                    let nOff := nP

                    for { let j := 0 } lt(j, k) { j := add(j, 1) } {
                        let nj := mload(nOff)
                        let lo := mul(m, nj)
                        let mmr := mulmod(m, nj, not(0))
                        let hi := sub(sub(mmr, lo), lt(mmr, lo))

                        let s1 := add(lo, mload(sOff))
                        let c1 := lt(s1, lo)
                        let s2 := add(s1, carry)
                        let c2 := lt(s2, s1)
                        mstore(sOff, s2)
                        carry := add(hi, add(c1, c2))

                        sOff := add(sOff, 0x20)
                        nOff := add(nOff, 0x20)
                    }

                    // Propagate carry into s[i+k..2k]
                    for {} gt(carry, 0) {} {
                        let val := mload(sOff)
                        let newVal := add(val, carry)
                        carry := lt(newVal, val)
                        mstore(sOff, newVal)
                        sOff := add(sOff, 0x20)
                    }

                    sBase := add(sBase, 0x20)
                }

                // ── Final conditional subtraction ──
                // Result is in s[k..2k-1], sBase points to s[k]
                {
                    let s2kOff := add(sP, mul(mul(k, 2), 0x20))
                    let doSub := gt(mload(s2kOff), 0)

                    if iszero(doSub) {
                        doSub := 1
                        for { let i := k } gt(i, 0) {} {
                            i := sub(i, 1)
                            let sL := mload(add(sBase, mul(i, 0x20)))
                            let nL := mload(add(nP, mul(i, 0x20)))
                            if gt(sL, nL) { i := 0 }
                            if lt(sL, nL) { doSub := 0 i := 0 }
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
