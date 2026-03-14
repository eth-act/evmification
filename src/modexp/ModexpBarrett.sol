// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {LimbMath} from "./LimbMath.sol";

/// @title ModexpBarrett
/// @notice Barrett-reduction modular exponentiation.
/// @dev Works for any modulus (odd or even). Readable style: Solidity for control flow,
///      assembly for hot-path arithmetic. May require `via_ir = true`.
library ModexpBarrett {
    /// @notice Computes base^exp mod modulus using Barrett reduction.
    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal pure returns (bytes memory result) {
        uint256 modLen = modulus.length;
        if (modLen == 0) return new bytes(0);

        result = new bytes(modLen);
        if (LimbMath.isZeroBytes(modulus) || LimbMath.isOneBytes(modulus)) return result;

        // Strip leading zero bytes so k reflects the actual modulus size.
        // Barrett requires that the top limb of n is non-zero.
        uint256 effectiveStart;
        assembly {
            let ptr := add(modulus, 0x20)
            let end := add(ptr, sub(modLen, 1))
            for {} and(lt(ptr, end), iszero(byte(0, mload(ptr)))) {} {
                ptr := add(ptr, 1)
            }
            effectiveStart := sub(ptr, add(modulus, 0x20))
        }
        if (effectiveStart > 0) {
            uint256 effectiveModLen = modLen - effectiveStart;
            bytes memory trimmedMod = new bytes(effectiveModLen);
            assembly {
                mcopy(add(trimmedMod, 0x20), add(add(modulus, 0x20), effectiveStart), effectiveModLen)
            }
            bytes memory trimmedResult = ModexpBarrett.modexp(base, exponent, trimmedMod);
            assembly {
                mcopy(add(add(result, 0x20), effectiveStart), add(trimmedResult, 0x20), effectiveModLen)
            }
            return result;
        }

        uint256 k = (modLen + 31) / 32;

        uint256[] memory n = LimbMath.bytesToLimbs(modulus, k);
        uint256[] memory a = LimbMath.reduceBase(base, n, k);

        // Barrett constant: mu = floor(2^(512k) / n), has k+1 limbs
        uint256[] memory mu = _computeBarrettConstant(n, k);

        // one = 1 as k-limb number (used as initial accumulator)
        uint256[] memory r = new uint256[](k);
        r[0] = 1;

        // Square-and-multiply
        r = _barrettModexpLoop(r, a, exponent, n, mu, k);

        LimbMath.limbsToBytes(r, result, modLen);
    }

    // ── Barrett constant computation ──────────────────────────────────

    /// @dev Computes mu = floor(2^(512k) / n).
    function _computeBarrettConstant(uint256[] memory n, uint256 k)
        private pure returns (uint256[] memory)
    {
        uint256 dLen = 2 * k + 1;
        uint256[] memory dividend = new uint256[](dLen);
        dividend[2 * k] = 1;
        (uint256[] memory mu,) = LimbMath.schoolbookDiv(dividend, dLen, n, k);
        return mu;
    }

    // ── Barrett multiply-reduce ───────────────────────────────────────

    /// @dev Computes (a * b) mod n using Barrett reduction.
    ///      a, b are k limbs; n is k limbs.
    function _barrettMulMod(
        uint256[] memory a,
        uint256[] memory b,
        uint256[] memory n,
        uint256[] memory mu,
        uint256 k
    ) private pure returns (uint256[] memory result) {
        // Step 1: product = a * b (2k limbs)
        uint256[] memory product = LimbMath.schoolbookMul(a, k, b, k);

        // Step 2: q1 = product >> (256*(k-1)) — top k+2 limbs
        uint256 q1Len = k + 2;
        uint256[] memory q1 = new uint256[](q1Len);
        {
            uint256 copyLen = k + 1;
            assembly {
                mcopy(
                    add(q1, 0x20),
                    add(add(product, 0x20), mul(sub(k, 1), 0x20)),
                    mul(copyLen, 0x20)
                )
            }
        }

        // Step 3: q2 = q1 * mu
        uint256 muLen = mu.length;
        uint256[] memory q2 = LimbMath.schoolbookMul(q1, q1Len, mu, muLen);

        // Step 4: q3 = q2 >> (256*(k+1)) — estimated quotient
        uint256 q2Len = q1Len + muLen;
        uint256 q3Len = q2Len > k + 1 ? q2Len - (k + 1) : 1;
        uint256[] memory q3 = new uint256[](q3Len);
        {
            uint256 copyLen = q2Len > k + 1 ? q2Len - (k + 1) : 0;
            if (copyLen > q3Len) copyLen = q3Len;
            assembly {
                mcopy(
                    add(q3, 0x20),
                    add(add(q2, 0x20), mul(add(k, 1), 0x20)),
                    mul(copyLen, 0x20)
                )
            }
        }

        // Step 5: r1 = product mod 2^(256*(k+1)) — bottom k+1 limbs
        uint256 rLen = k + 1;

        // Step 6: r2 = (q3 * n) mod 2^(256*(k+1)) — truncated multiply
        uint256[] memory r2 = new uint256[](rLen);
        assembly {
            let q3P := add(q3, 0x20)
            let nP := add(n, 0x20)
            let r2P := add(r2, 0x20)

            for { let i := 0 } lt(i, q3Len) { i := add(i, 1) } {
                let qi := mload(add(q3P, mul(i, 0x20)))
                if gt(qi, 0) {
                    let carry := 0
                    let jMax := sub(rLen, i)
                    if gt(jMax, k) { jMax := k }
                    for { let j := 0 } lt(j, jMax) { j := add(j, 1) } {
                        let rOff := add(r2P, mul(add(i, j), 0x20))
                        let nj := mload(add(nP, mul(j, 0x20)))

                        let lo := mul(qi, nj)
                        let mmr := mulmod(qi, nj, not(0))
                        let hi := sub(sub(mmr, lo), lt(mmr, lo))

                        let s1 := add(lo, mload(rOff))
                        let c1 := lt(s1, lo)
                        let s2 := add(s1, carry)
                        mstore(rOff, s2)
                        carry := add(hi, add(c1, lt(s2, s1)))
                    }
                    let finalIdx := add(i, jMax)
                    if lt(finalIdx, rLen) {
                        let rOff := add(r2P, mul(finalIdx, 0x20))
                        mstore(rOff, add(mload(rOff), carry))
                    }
                }
            }
        }

        // Step 7: r = r1 - r2 (mod 2^(256*(k+1))), then correct
        result = new uint256[](k);
        assembly {
            let pP := add(product, 0x20)
            let r2P := add(r2, 0x20)
            let resP := add(result, 0x20)
            let nP := add(n, 0x20)

            // Subtract r2 from product[0..k] into r2 (in-place reuse)
            let borrow := 0
            for { let i := 0 } lt(i, rLen) { i := add(i, 1) } {
                let pi := mload(add(pP, mul(i, 0x20)))
                let ri := mload(add(r2P, mul(i, 0x20)))
                let d := sub(pi, ri)
                let nb := lt(pi, ri)
                let d2 := sub(d, borrow)
                nb := or(nb, lt(d, borrow))
                borrow := nb
                mstore(add(r2P, mul(i, 0x20)), d2)
            }

            // Correct: subtract n at most twice (Barrett guarantee)
            for { let iter := 0 } lt(iter, 2) { iter := add(iter, 1) } {
                let geq := gt(mload(add(r2P, mul(k, 0x20))), 0)
                if iszero(geq) {
                    geq := 1
                    for { let i := k } gt(i, 0) {} {
                        i := sub(i, 1)
                        let rL := mload(add(r2P, mul(i, 0x20)))
                        let nL := mload(add(nP, mul(i, 0x20)))
                        if gt(rL, nL) { i := 0 }
                        if lt(rL, nL) { geq := 0 i := 0 }
                    }
                }

                if iszero(geq) { iter := 2 }
                if geq {
                    let brw := 0
                    for { let i := 0 } lt(i, rLen) { i := add(i, 1) } {
                        let rOff := add(r2P, mul(i, 0x20))
                        let rL := mload(rOff)
                        let nL := 0
                        if lt(i, k) { nL := mload(add(nP, mul(i, 0x20))) }
                        let dd := sub(rL, nL)
                        let nbb := lt(rL, nL)
                        let dd2 := sub(dd, brw)
                        nbb := or(nbb, lt(dd, brw))
                        brw := nbb
                        mstore(rOff, dd2)
                    }
                }
            }

            // Copy final result
            mcopy(resP, r2P, mul(k, 0x20))
        }
    }

    // ── Exponentiation loop ───────────────────────────────────────────

    /// @dev Left-to-right binary square-and-multiply using Barrett reduction.
    ///      Recycles temporary memory each iteration to avoid MemoryOOG on large exponents.
    function _barrettModexpLoop(
        uint256[] memory r,
        uint256[] memory a,
        bytes memory exponent,
        uint256[] memory n,
        uint256[] memory mu,
        uint256 k
    ) private pure returns (uint256[] memory) {
        uint256 expLen = exponent.length;

        uint256 startByte = 0;
        while (startByte < expLen && exponent[startByte] == 0) {
            startByte++;
        }
        if (startByte == expLen) return r;

        // Save free memory pointer; all temporaries from _barrettMulMod will be
        // allocated above this mark and reclaimed each iteration.
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }

        // Find the top set bit in the first non-zero byte
        uint8 b = uint8(exponent[startByte]);
        uint256 topBit = 7;
        while (topBit > 0 && (b >> topBit) & 1 == 0) {
            topBit--;
        }

        // Unified square-and-multiply loop across all exponent bytes
        bool started = false;
        for (uint256 byteIdx = startByte; byteIdx < expLen; byteIdx++) {
            b = uint8(exponent[byteIdx]);
            uint256 highBit = started ? 7 : topBit;
            started = true;
            for (uint256 bit = highBit + 1; bit > 0;) {
                unchecked { bit--; }
                assembly { mstore(0x40, freeMemBase) }
                LimbMath.copyLimbs(_barrettMulMod(r, r, n, mu, k), r, k);
                if ((b >> bit) & 1 == 1) {
                    assembly { mstore(0x40, freeMemBase) }
                    LimbMath.copyLimbs(_barrettMulMod(r, a, n, mu, k), r, k);
                }
            }
        }

        return r;
    }
}
