// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library ModexpMontgomery {
    function modexp(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal view returns (bytes memory result) {
        // Return zero-length if modulus is empty
        uint256 modLen = modulus.length;
        if (modLen == 0) {
            return new bytes(0);
        }

        // Allocate result with same length as modulus
        result = new bytes(modLen);

        assembly {
            // ============================================================
            //  Context layout in memory:
            //    ctx + 0x00:  k (number of limbs)
            //    ctx + 0x20:  n0inv (Montgomery constant)
            //    ctx + 0x40:  start of arrays
            //  Array layout (arrayBase = ctx + 0x40):
            //    nP       = arrayBase
            //    aP       = arrayBase + k*32
            //    rP       = arrayBase + 2*k*32
            //    tP       = arrayBase + 3*k*32        [(k+2) limbs]
            //    r2P      = arrayBase + (4*k+2)*32
            //    scratchP = arrayBase + (5*k+2)*32
            //    oneP     = arrayBase + (6*k+2)*32
            //    end      = arrayBase + (7*k+2)*32
            // ============================================================

            function getK(ctx) -> v { v := mload(ctx) }
            function getN0inv(ctx) -> v { v := mload(add(ctx, 0x20)) }
            function getNP(ctx) -> p { p := add(ctx, 0x40) }
            function getAP(ctx) -> p {
                p := add(add(ctx, 0x40), mul(mload(ctx), 32))
            }
            function getRP(ctx) -> p {
                p := add(add(ctx, 0x40), mul(mload(ctx), 64))
            }
            function getTP(ctx) -> p {
                p := add(add(ctx, 0x40), mul(mload(ctx), 96))
            }
            function getR2P(ctx) -> p {
                p := add(add(ctx, 0x80), mul(mload(ctx), 128))
            }
            function getScratchP(ctx) -> p {
                p := add(add(ctx, 0x80), mul(mload(ctx), 160))
            }
            function getOneP(ctx) -> p {
                p := add(add(ctx, 0x80), mul(mload(ctx), 192))
            }

            // ============================================================
            //  Helper: Compare two k-limb numbers
            //  Returns 1 if a >= b, 0 otherwise
            // ============================================================
            function limbGte(aPtr, bPtr, kk) -> res {
                let i := kk
                for {} gt(i, 0) {} {
                    i := sub(i, 1)
                    let aL := mload(add(aPtr, mul(i, 32)))
                    let bL := mload(add(bPtr, mul(i, 32)))
                    if gt(aL, bL) { res := 1 leave }
                    if lt(aL, bL) { res := 0 leave }
                }
                res := 1
            }

            // ============================================================
            //  Helper: Subtract bPtr from aPtr in place (k limbs)
            // ============================================================
            function limbSub(aPtr, bPtr, kk) {
                let borrow := 0
                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    let off := add(aPtr, mul(i, 32))
                    let aL := mload(off)
                    let bL := mload(add(bPtr, mul(i, 32)))
                    let d := sub(aL, bL)
                    let nb := lt(aL, bL)
                    let d2 := sub(d, borrow)
                    borrow := or(nb, lt(d, borrow))
                    mstore(off, d2)
                }
            }

            // ============================================================
            //  Helper: Copy k limbs from src to dst
            // ============================================================
            function copyLimbs(dst, src, kk) {
                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    mstore(add(dst, mul(i, 32)), mload(add(src, mul(i, 32))))
                }
            }

            // ============================================================
            //  Helper: Zero k limbs
            // ============================================================
            function zeroLimbs(ptr, kk) {
                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    mstore(add(ptr, mul(i, 32)), 0)
                }
            }

            // ============================================================
            //  Helper: Convert big-endian bytes to LE limbs
            // ============================================================
            function bytesToLimbs(dataPtr, dataLen, limbPtr) {
                let fullLimbs := div(dataLen, 32)
                for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                    mstore(
                        add(limbPtr, mul(i, 32)),
                        mload(add(dataPtr, sub(dataLen, mul(add(i, 1), 32))))
                    )
                }
                let rem := mod(dataLen, 32)
                if rem {
                    mstore(
                        add(limbPtr, mul(fullLimbs, 32)),
                        shr(mul(sub(32, rem), 8), mload(dataPtr))
                    )
                }
            }

            // ============================================================
            //  Helper: Convert LE limbs to big-endian bytes
            // ============================================================
            function limbsToBytes(limbPtr, outPtr, dataLen) {
                let fullLimbs := div(dataLen, 32)
                for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                    mstore(
                        add(outPtr, sub(dataLen, mul(add(i, 1), 32))),
                        mload(add(limbPtr, mul(i, 32)))
                    )
                }
                let rem := mod(dataLen, 32)
                if rem {
                    let limbVal := mload(add(limbPtr, mul(fullLimbs, 32)))
                    let shift := mul(sub(32, rem), 8)
                    let shifted := shl(shift, limbVal)
                    let existing := mload(outPtr)
                    let mask := not(sub(shl(shift, 1), 1))
                    mstore(outPtr, or(and(shifted, mask), and(existing, not(mask))))
                }
            }

            // ============================================================
            //  Montgomery multiply pass: accumulate ai * b[] into t[]
            //  and propagate carry into t[k], t[k+1].
            //  Minimized stack: 3 params, carefully reuse vars in loop.
            // ============================================================
            function montMulPass(ai, bP, tP, kk) {
                let carry := 0
                for { let j := 0 } lt(j, kk) { j := add(j, 1) } {
                    // We carefully minimize live variables here.
                    // Live at loop top: ai(1), bP(2), tP(3), kk(4), carry(5), j(6) = 6
                    let tOff := add(tP, mul(j, 32))

                    // (hi, lo) = ai * b[j]
                    let lo := mul(ai, mload(add(bP, mul(j, 32))))
                    let hi := sub(
                        sub(mulmod(ai, mload(add(bP, mul(j, 32))), not(0)), lo),
                        lt(mulmod(ai, mload(add(bP, mul(j, 32))), not(0)), lo)
                    )

                    // sum = lo + t[j] + carry; new_carry = hi + overflow_bits
                    let s := add(lo, mload(tOff))
                    let c1 := lt(s, lo)
                    let s2 := add(s, carry)
                    mstore(tOff, s2)
                    carry := add(hi, add(c1, lt(s2, s)))
                }

                // Propagate carry into t[k] and t[k+1]
                {
                    let tkOff := add(tP, mul(kk, 32))
                    let tk := mload(tkOff)
                    let tkNew := add(tk, carry)
                    mstore(tkOff, tkNew)
                    let tk1Off := add(tP, mul(add(kk, 1), 32))
                    mstore(tk1Off, add(mload(tk1Off), lt(tkNew, tk)))
                }
            }

            // ============================================================
            //  Montgomery reduce pass: compute m = t[0]*n0inv,
            //  accumulate m*n[] into t[] with shift down.
            // ============================================================
            function montReducePass(nP, tP, n0inv, kk) {
                let m := mul(mload(tP), n0inv)

                let carry := 0
                for { let j := 0 } lt(j, kk) { j := add(j, 1) } {
                    let tOff := add(tP, mul(j, 32))

                    let lo := mul(m, mload(add(nP, mul(j, 32))))
                    let hi := sub(
                        sub(mulmod(m, mload(add(nP, mul(j, 32))), not(0)), lo),
                        lt(mulmod(m, mload(add(nP, mul(j, 32))), not(0)), lo)
                    )

                    let s := add(lo, mload(tOff))
                    let c1 := lt(s, lo)
                    let s2 := add(s, carry)
                    let c2 := lt(s2, s)

                    if gt(j, 0) {
                        mstore(add(tP, mul(sub(j, 1), 32)), s2)
                    }

                    carry := add(hi, add(c1, c2))
                }

                // Handle upper limbs with shift
                {
                    let tkVal := mload(add(tP, mul(kk, 32)))
                    let sum := add(tkVal, carry)
                    mstore(add(tP, mul(sub(kk, 1), 32)), sum)

                    let tk1Off := add(tP, mul(add(kk, 1), 32))
                    mstore(add(tP, mul(kk, 32)), add(mload(tk1Off), lt(sum, tkVal)))
                    mstore(tk1Off, 0)
                }
            }

            // ============================================================
            //  Montgomery multiplication (CIOS) using context
            //  Computes resP = aP * bP * R^{-1} mod n
            // ============================================================
            function montMul(ctx, resP, aP, bP) {
                let kk := getK(ctx)
                let tP := getTP(ctx)

                // Zero out t[0..k+1]
                zeroLimbs(tP, add(kk, 2))

                // Main CIOS loop
                {
                    let nP := getNP(ctx)
                    let n0inv := getN0inv(ctx)
                    for { let ii := 0 } lt(ii, kk) { ii := add(ii, 1) } {
                        montMulPass(mload(add(aP, mul(ii, 32))), bP, tP, kk)
                        montReducePass(nP, tP, n0inv, kk)
                    }
                }

                // Final conditional subtraction
                {
                    let nP := getNP(ctx)
                    let doSub := 0
                    if gt(mload(add(tP, mul(kk, 32))), 0) { doSub := 1 }
                    if iszero(doSub) {
                        doSub := limbGte(tP, nP, kk)
                    }
                    copyLimbs(resP, tP, kk)
                    if doSub { limbSub(resP, nP, kk) }
                }
            }

            // ============================================================
            //  Setup modulus - convert bytes to limbs at nP
            // ============================================================
            function setupModulus(ctx, modData, mLen) {
                let kk := getK(ctx)
                let nP := getNP(ctx)
                zeroLimbs(nP, kk)
                bytesToLimbs(modData, mLen, nP)
            }

            // ============================================================
            //  Reduce base mod n using precompile, store at aP
            // ============================================================
            function setupBase(ctx, basePtr, modData, mLen) {
                let kk := getK(ctx)
                let aP := getAP(ctx)
                let baseLen := mload(basePtr)

                let inputLen := add(add(97, baseLen), mLen)
                let inputP := mload(0x40)
                mstore(0x40, add(inputP, inputLen))
                mstore(inputP, baseLen)
                mstore(add(inputP, 0x20), 1)
                mstore(add(inputP, 0x40), mLen)

                // Copy base data
                {
                    let bData := add(basePtr, 0x20)
                    for { let i := 0 } lt(i, baseLen) { i := add(i, 32) } {
                        mstore(add(add(inputP, 96), i), mload(add(bData, i)))
                    }
                }

                mstore8(add(inputP, add(96, baseLen)), 1)

                // Copy modulus data
                {
                    let dst := add(inputP, add(97, baseLen))
                    for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                        mstore(add(dst, i), mload(add(modData, i)))
                    }
                }

                let outP := mload(0x40)
                mstore(0x40, add(outP, mLen))
                let success := staticcall(gas(), 0x05, inputP, inputLen, outP, mLen)
                if iszero(success) { revert(0, 0) }

                zeroLimbs(aP, kk)
                bytesToLimbs(outP, mLen, aP)
            }

            // ============================================================
            //  Compute Montgomery inverse n0inv
            // ============================================================
            function computeN0inv(ctx) {
                let n0 := mload(getNP(ctx))
                let inv := 1
                for { let iter := 0 } lt(iter, 8) { iter := add(iter, 1) } {
                    inv := mul(inv, sub(2, mul(n0, inv)))
                }
                mstore(add(ctx, 0x20), sub(0, inv))
            }

            // ============================================================
            //  Compute R^2 mod n using precompile
            // ============================================================
            function computeR2(ctx, modData, mLen) {
                let kk := getK(ctx)
                let r2P := getR2P(ctx)
                let expVal := mul(512, kk)

                let expByteLen := 0
                {
                    let tmp := expVal
                    for {} gt(tmp, 0) {} {
                        expByteLen := add(expByteLen, 1)
                        tmp := shr(8, tmp)
                    }
                    if iszero(expByteLen) { expByteLen := 1 }
                }

                let inputLen := add(add(97, expByteLen), mLen)
                let inputP := mload(0x40)
                mstore(0x40, add(inputP, add(inputLen, 32)))
                mstore(inputP, 1)
                mstore(add(inputP, 0x20), expByteLen)
                mstore(add(inputP, 0x40), mLen)
                mstore8(add(inputP, 96), 2)

                {
                    let expOff := add(inputP, 97)
                    let tmp := expVal
                    for { let b := 0 } lt(b, expByteLen) { b := add(b, 1) } {
                        mstore8(add(expOff, sub(sub(expByteLen, 1), b)), and(tmp, 0xff))
                        tmp := shr(8, tmp)
                    }
                }

                {
                    let modOff := add(inputP, add(97, expByteLen))
                    for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                        mstore(add(modOff, i), mload(add(modData, i)))
                    }
                }

                let outP := mload(0x40)
                mstore(0x40, add(outP, add(mLen, 32)))
                let success := staticcall(gas(), 0x05, inputP, inputLen, outP, mLen)
                if iszero(success) { revert(0, 0) }

                zeroLimbs(r2P, kk)
                bytesToLimbs(outP, mLen, r2P)
            }

            // ============================================================
            //  Convert base to Montgomery form
            // ============================================================
            function convertToMontgomery(ctx) {
                let scrP := getScratchP(ctx)
                let aP := getAP(ctx)
                montMul(ctx, scrP, aP, getR2P(ctx))
                copyLimbs(aP, scrP, getK(ctx))
            }

            // ============================================================
            //  Initialize result as R mod n (Montgomery form of 1)
            // ============================================================
            function initResult(ctx) {
                montMul(ctx, getRP(ctx), getOneP(ctx), getR2P(ctx))
            }

            // ============================================================
            //  Process a single exponent byte from topBit down to 0
            // ============================================================
            function processExpByte(ctx, b, topBit) {
                let kk := getK(ctx)
                let rP := getRP(ctx)
                let scrP := getScratchP(ctx)

                let bit := topBit
                for {} iszero(gt(bit, topBit)) {} {
                    // Square: r = r * r
                    montMul(ctx, scrP, rP, rP)
                    copyLimbs(rP, scrP, kk)

                    // If bit set, multiply: r = r * a
                    if and(b, shl(bit, 1)) {
                        montMul(ctx, scrP, rP, getAP(ctx))
                        copyLimbs(rP, scrP, kk)
                    }

                    if iszero(bit) { break }
                    bit := sub(bit, 1)
                }
            }

            // ============================================================
            //  Square-and-multiply exponentiation
            // ============================================================
            function doExponentiation(ctx, expPtr) {
                let expData := add(expPtr, 0x20)
                let expLen := mload(expPtr)

                let startByte := 0
                for {} lt(startByte, expLen) { startByte := add(startByte, 1) } {
                    if byte(0, mload(add(expData, startByte))) { break }
                }

                if lt(startByte, expLen) {
                    let firstByte := byte(0, mload(add(expData, startByte)))

                    let topBit := 7
                    for {} gt(topBit, 0) {} {
                        if and(firstByte, shl(topBit, 1)) { break }
                        topBit := sub(topBit, 1)
                    }

                    processExpByte(ctx, firstByte, topBit)

                    let byteIdx := add(startByte, 1)
                    for {} lt(byteIdx, expLen) { byteIdx := add(byteIdx, 1) } {
                        processExpByte(ctx, byte(0, mload(add(expData, byteIdx))), 7)
                    }
                }
            }

            // ============================================================
            //  Convert out of Montgomery form and write result bytes
            // ============================================================
            function convertResult(ctx, resultPtr, mLen) {
                let scrP := getScratchP(ctx)
                montMul(ctx, scrP, getRP(ctx), getOneP(ctx))
                let resData := add(resultPtr, 0x20)
                for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                    mstore(add(resData, i), 0)
                }
                limbsToBytes(scrP, resData, mLen)
            }

            // ============================================================
            //  MAIN LOGIC
            // ============================================================

            let modData := add(modulus, 0x20)
            let mLen := mload(modulus)
            let k := div(add(mLen, 31), 32)

            // Check modulus == 0
            let modIsZero := 1
            for { let i := 0 } lt(i, mLen) { i := add(i, 1) } {
                if byte(0, mload(add(modData, i))) {
                    modIsZero := 0
                    i := mLen
                }
            }

            if iszero(modIsZero) {
                // Check modulus == 1
                let modIsOne := 0
                {
                    let ok := 1
                    for { let i := 0 } lt(i, sub(mLen, 1)) { i := add(i, 1) } {
                        if byte(0, mload(add(modData, i))) {
                            ok := 0
                            i := mLen
                        }
                    }
                    if ok {
                        if eq(byte(0, mload(add(modData, sub(mLen, 1)))), 1) {
                            modIsOne := 1
                        }
                    }
                }

                if iszero(modIsOne) {
                    let ctx := mload(0x40)
                    mstore(ctx, k)
                    mstore(0x40, add(add(ctx, 0x40), mul(add(mul(7, k), 2), 32)))

                    setupModulus(ctx, modData, mLen)
                    setupBase(ctx, base, modData, mLen)

                    {
                        let oneP := getOneP(ctx)
                        zeroLimbs(oneP, k)
                        mstore(oneP, 1)
                    }

                    computeN0inv(ctx)
                    computeR2(ctx, modData, mLen)
                    convertToMontgomery(ctx)
                    initResult(ctx)
                    doExponentiation(ctx, exponent)
                    convertResult(ctx, result, mLen)
                }
            }
        }
    }
}
