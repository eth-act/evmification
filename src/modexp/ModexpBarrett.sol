// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


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
    ) internal view returns (bytes memory result) {
        uint256 modLen = modulus.length;
        if (modLen == 0) return new bytes(0);

        result = new bytes(modLen);
        if (_isZeroBytes(modulus) || _isOneBytes(modulus)) return result;

        // Strip leading zero bytes so k reflects the actual modulus size.
        // Barrett requires that the top limb of n is non-zero.
        uint256 effectiveStart = 0;
        while (effectiveStart < modLen - 1 && modulus[effectiveStart] == 0) {
            effectiveStart++;
        }
        if (effectiveStart > 0) {
            uint256 effectiveModLen = modLen - effectiveStart;
            bytes memory trimmedMod = new bytes(effectiveModLen);
            for (uint256 i = 0; i < effectiveModLen; i++) {
                trimmedMod[i] = modulus[effectiveStart + i];
            }
            bytes memory trimmedResult = ModexpBarrett.modexp(base, exponent, trimmedMod);
            for (uint256 i = 0; i < effectiveModLen; i++) {
                result[effectiveStart + i] = trimmedResult[i];
            }
            return result;
        }

        uint256 k = (modLen + 31) / 32;

        uint256[] memory n = _bytesToLimbs(modulus, k);
        uint256[] memory a = _reduceBase(base, modulus, k);

        // Barrett constant: mu = floor(2^(512k) / n), has k+1 limbs
        uint256[] memory mu = _computeBarrettConstant(n, k, modulus);

        // one = 1 as k-limb number (used as initial accumulator)
        uint256[] memory r = new uint256[](k);
        r[0] = 1;

        // Square-and-multiply
        r = _barrettModexpLoop(r, a, exponent, n, mu, k);

        _limbsToBytes(r, result, modLen);
    }

    // ── Byte-level helpers ────────────────────────────────────────────

    function _isZeroBytes(bytes memory b) private pure returns (bool) {
        for (uint256 i = 0; i < b.length; i++) {
            if (b[i] != 0) return false;
        }
        return true;
    }

    function _isOneBytes(bytes memory b) private pure returns (bool) {
        uint256 len = b.length;
        for (uint256 i = 0; i < len - 1; i++) {
            if (b[i] != 0) return false;
        }
        return b[len - 1] == 0x01;
    }

    // ── Limb conversion ──────────────────────────────────────────────

    function _bytesToLimbs(bytes memory data, uint256 k) private pure returns (uint256[] memory limbs) {
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

    // ── Precompile wrapper ────────────────────────────────────────────

    function _callPrecompile(bytes memory b, bytes memory e, bytes memory m)
        private view returns (bytes memory result)
    {
        uint256 modLen = m.length;
        result = new bytes(modLen);
        bytes memory input = abi.encodePacked(
            uint256(b.length), uint256(e.length), uint256(modLen), b, e, m
        );
        assembly {
            let ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(result, 0x20), modLen)
            if iszero(ok) { revert(0, 0) }
        }
    }

    function _reduceBase(bytes memory base, bytes memory modulus, uint256 k)
        private view returns (uint256[] memory)
    {
        return _bytesToLimbs(_callPrecompile(base, hex"01", modulus), k);
    }

    function _uint256ToMinBytes(uint256 val) private pure returns (bytes memory) {
        if (val == 0) return hex"00";
        uint256 byteLen = 0;
        uint256 tmp = val;
        while (tmp > 0) {
            byteLen++;
            tmp >>= 8;
        }
        bytes memory result = new bytes(byteLen);
        unchecked {
            for (uint256 i = 0; i < byteLen; i++) {
                result[byteLen - 1 - i] = bytes1(uint8(val));
                val >>= 8;
            }
        }
        return result;
    }

    // ── Barrett constant computation ──────────────────────────────────

    /// @dev Computes mu = floor(2^(512k) / n).
    function _computeBarrettConstant(uint256[] memory n, uint256 k, bytes memory modulus)
        private view returns (uint256[] memory)
    {
        // r = 2^(512k) mod n via precompile
        uint256 expVal = 512 * k;
        bytes memory expBytes = _uint256ToMinBytes(expVal);
        bytes memory base2 = new bytes(1);
        base2[0] = 0x02;
        uint256[] memory r = _bytesToLimbs(_callPrecompile(base2, expBytes, modulus), k);

        // dividend = 2^(512k) - r, which is exactly divisible by n
        // dividend has 2k+1 limbs: limbs 0..k-1 = two's complement of r, limb 2k = 1
        uint256 dLen = 2 * k + 1;
        uint256[] memory dividend = new uint256[](dLen);

        // Compute -r mod 2^(256k), i.e., two's complement
        assembly {
            let divP := add(dividend, 0x20)
            let rP := add(r, 0x20)
            let borrow := 0
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let ri := mload(add(rP, mul(i, 0x20)))
                let d := sub(sub(0, ri), borrow)
                borrow := or(gt(ri, 0), and(iszero(ri), borrow))
                mstore(add(divP, mul(i, 0x20)), d)
            }
            for { let i := k } lt(i, mul(2, k)) { i := add(i, 1) } {
                let d := sub(0, borrow)
                mstore(add(divP, mul(i, 0x20)), d)
            }
            mstore(add(divP, mul(mul(2, k), 0x20)), sub(1, borrow))
        }

        // mu = dividend / n via schoolbook division
        return _schoolbookDiv(dividend, dLen, n, k);
    }

    // ── Division helpers ──────────────────────────────────────────────

    /// @dev 512-by-256 division: (hi:lo) / d -> (quotient, remainder).
    ///      Requires hi < d (quotient fits in 256 bits).
    ///      Uses mulmod/addmod for remainder, then modular-inverse for exact quotient
    ///      (Uniswap V3 / Solmate technique).
    function _div512by256(uint256 hi, uint256 lo, uint256 d)
        private pure returns (uint256 q, uint256 rem)
    {
        assembly {
            if iszero(hi) {
                q := div(lo, d)
                rem := mod(lo, d)
            }
            if gt(hi, 0) {
                // Step 1: remainder = (hi * 2^256 + lo) mod d
                let r256 := addmod(mod(not(0), d), 1, d)
                rem := addmod(mulmod(hi, r256, d), lo, d)

                // Step 2: exact numerator = (hi * 2^256 + lo) - rem = q * d
                let lo_e := sub(lo, rem)
                let hi_e := sub(hi, lt(lo, rem))

                // Step 3: factor out largest power of 2 from d
                let twos := and(d, sub(0, d))
                d := div(d, twos)

                // Step 4: divide exact numerator by twos
                lo_e := div(lo_e, twos)
                let flip := add(div(sub(0, twos), twos), 1)
                lo_e := or(lo_e, mul(hi_e, flip))

                // Step 5: modular inverse of d (now odd) mod 2^256
                let inv := xor(mul(3, d), 2)
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))
                inv := mul(inv, sub(2, mul(d, inv)))

                // Step 6: quotient
                q := mul(lo_e, inv)
            }
        }
    }

    /// @dev Schoolbook long division: dividend[0..dLen-1] / divisor[0..k-1].
    ///      All arrays are little-endian limbs.
    function _schoolbookDiv(
        uint256[] memory dividend,
        uint256 dLen,
        uint256[] memory divisor,
        uint256 k
    ) private pure returns (uint256[] memory quotient) {
        // Find actual length of dividend (strip leading zero limbs)
        uint256 m = dLen;
        while (m > 0 && dividend[m - 1] == 0) {
            m--;
        }
        if (m == 0) {
            quotient = new uint256[](1);
            return quotient;
        }

        // Find effective number of significant limbs in divisor
        uint256 kEff = k;
        while (kEff > 1 && divisor[kEff - 1] == 0) {
            kEff--;
        }

        // Single-limb effective divisor: use simple division
        if (kEff == 1) {
            uint256 d = divisor[0];
            quotient = new uint256[](m);
            uint256 remainder = 0;
            for (uint256 i = m; i > 0;) {
                unchecked { i--; }
                uint256 q;
                (q, remainder) = _div512by256(remainder, dividend[i], d);
                quotient[i] = q;
            }
            return quotient;
        }

        // Multi-limb divisor: Knuth Algorithm D (using kEff significant limbs)
        if (m < kEff) {
            quotient = new uint256[](1);
            return quotient;
        }
        uint256 numQlimbs = m - kEff + 1;
        quotient = new uint256[](numQlimbs);

        uint256[] memory u = new uint256[](m + 1);
        for (uint256 i = 0; i < m; i++) {
            u[i] = dividend[i];
        }

        // Normalize: shift divisor so top limb has high bit set
        uint256 topD = divisor[kEff - 1];
        uint256 shift = 0;
        {
            uint256 tmp = topD;
            while (tmp < (1 << 255)) {
                tmp <<= 1;
                shift++;
            }
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
            for (uint256 i = 0; i < kEff; i++) {
                v[i] = divisor[i];
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
                    doRefinement = (rHat >= uLo); // false if rHat overflowed
                } else {
                    (qHat, rHat) = _div512by256(uHi, uLo, vTop);
                    doRefinement = true;
                }

                // Knuth Algorithm D refinement: ensure qHat <= q + 1
                // Check: qHat * v[kEff-2] > rHat * b + u[jj + kEff - 2]
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

        return quotient;
    }

    // ── Schoolbook multiplication ─────────────────────────────────────

    /// @dev Schoolbook multiply: result = a[0..aLen-1] * b[0..bLen-1].
    ///      Returns (aLen + bLen) limbs.
    function _schoolbookMul(
        uint256[] memory a,
        uint256 aLen,
        uint256[] memory b,
        uint256 bLen
    ) private pure returns (uint256[] memory result) {
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
        uint256[] memory product = _schoolbookMul(a, k, b, k);

        // Step 2: q1 = product >> (256*(k-1)) — top k+2 limbs
        uint256 q1Len = k + 2;
        uint256[] memory q1 = new uint256[](q1Len);
        for (uint256 i = 0; i < q1Len; i++) {
            uint256 srcIdx = i + k - 1;
            if (srcIdx < 2 * k) {
                q1[i] = product[srcIdx];
            }
        }

        // Step 3: q2 = q1 * mu
        uint256 muLen = mu.length;
        uint256[] memory q2 = _schoolbookMul(q1, q1Len, mu, muLen);

        // Step 4: q3 = q2 >> (256*(k+1)) — estimated quotient
        uint256 q2Len = q1Len + muLen;
        uint256 q3Len = q2Len > k + 1 ? q2Len - (k + 1) : 1;
        uint256[] memory q3 = new uint256[](q3Len);
        for (uint256 i = 0; i < q3Len; i++) {
            uint256 srcIdx = i + k + 1;
            if (srcIdx < q2Len) {
                q3[i] = q2[srcIdx];
            }
        }

        // Step 5: r1 = product mod 2^(256*(k+1)) — bottom k+1 limbs
        uint256 rLen = k + 1;

        // Step 6: r2 = (q3 * n) mod 2^(256*(k+1)) — bottom k+1 limbs
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

        // Debug: log intermediate values
        // Step 7: r = r1 - r2 (mod 2^(256*(k+1))), then correct
        result = new uint256[](k);
        assembly {
            let pP := add(product, 0x20)
            let r2P := add(r2, 0x20)
            let resP := add(result, 0x20)
            let nP := add(n, 0x20)

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

            // Correct: subtract n at most twice
            for { let iter := 0 } lt(iter, 3) { iter := add(iter, 1) } {
                let topR := mload(add(r2P, mul(k, 0x20)))
                let geq := 0
                if gt(topR, 0) { geq := 1 }
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

                if iszero(geq) {
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        mstore(add(resP, mul(i, 0x20)), mload(add(r2P, mul(i, 0x20))))
                    }
                    iter := 3
                }
                if gt(geq, 0) {
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

        uint8 b = uint8(exponent[startByte]);
        uint256 topBit = 7;
        while (topBit > 0 && (b >> topBit) & 1 == 0) {
            topBit--;
        }

        for (uint256 bit = topBit;;) {
            assembly { mstore(0x40, freeMemBase) }
            _copyLimbs(_barrettMulMod(r, r, n, mu, k), r, k);
            if ((b >> bit) & 1 == 1) {
                assembly { mstore(0x40, freeMemBase) }
                _copyLimbs(_barrettMulMod(r, a, n, mu, k), r, k);
            }
            if (bit == 0) break;
            unchecked { bit--; }
        }

        for (uint256 byteIdx = startByte + 1; byteIdx < expLen; byteIdx++) {
            b = uint8(exponent[byteIdx]);
            for (uint256 bit = 8; bit > 0;) {
                unchecked { bit--; }
                assembly { mstore(0x40, freeMemBase) }
                _copyLimbs(_barrettMulMod(r, r, n, mu, k), r, k);
                if ((b >> bit) & 1 == 1) {
                    assembly { mstore(0x40, freeMemBase) }
                    _copyLimbs(_barrettMulMod(r, a, n, mu, k), r, k);
                }
            }
        }

        return r;
    }

    /// @dev Copy `len` limbs from `src` into `dst` (in-place overwrite).
    function _copyLimbs(uint256[] memory src, uint256[] memory dst, uint256 len) private pure {
        assembly {
            let s := add(src, 0x20)
            let d := add(dst, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(add(d, mul(i, 0x20)), mload(add(s, mul(i, 0x20))))
            }
        }
    }
}
