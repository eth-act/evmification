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

        // If modulus is all zeros, result is already zeros
        // If modulus length is not a multiple of 32, we need to pad
        // We'll handle everything inside assembly for efficiency

        assembly {
            // ============================================================
            //  Helper: 256x256 -> 512 full multiplication
            //  Returns (hi, lo) = a * b
            // ============================================================
            function fullMul(a, b) -> hi, lo {
                lo := mul(a, b)
                let mm := mulmod(a, b, not(0))
                hi := sub(sub(mm, lo), lt(mm, lo))
            }

            // ============================================================
            //  Helper: Compare two k-limb numbers at aP and bP
            //  Returns 1 if a >= b, 0 otherwise
            //  Limbs are little-endian (limb 0 = LSB at offset 0)
            // ============================================================
            function limbGte(aP, bP, kk) -> res {
                // Compare from most significant limb down
                let i := kk
                for {} gt(i, 0) {} {
                    i := sub(i, 1)
                    let aLimb := mload(add(aP, mul(i, 32)))
                    let bLimb := mload(add(bP, mul(i, 32)))
                    if gt(aLimb, bLimb) {
                        res := 1
                        leave
                    }
                    if lt(aLimb, bLimb) {
                        res := 0
                        leave
                    }
                }
                // Equal
                res := 1
            }

            // ============================================================
            //  Helper: Subtract bP from aP, store in aP (k limbs)
            //  Assumes a >= b
            // ============================================================
            function limbSub(aP, bP, kk) {
                let borrow := 0
                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    let aOff := add(aP, mul(i, 32))
                    let aLimb := mload(aOff)
                    let bLimb := mload(add(bP, mul(i, 32)))
                    let diff := sub(aLimb, bLimb)
                    let newBorrow := lt(aLimb, bLimb)
                    let diff2 := sub(diff, borrow)
                    let newBorrow2 := lt(diff, borrow)
                    borrow := or(newBorrow, newBorrow2)
                    mstore(aOff, diff2)
                }
            }

            // ============================================================
            //  Helper: Montgomery multiplication (CIOS)
            //  Computes a*b*R^{-1} mod n, stores result at resP
            //  aP, bP, nP: pointers to k-limb arrays (little-endian)
            //  tP: pointer to (k+2)-limb scratch space
            //  n0inv: Montgomery inverse (-n^{-1} mod 2^256)
            //  kk: number of limbs
            // ============================================================
            function montMul(resP, aP, bP, nP, tP, n0inv, kk) {
                // Zero out t[0..k+1]
                let tSize := add(kk, 2)
                for { let i := 0 } lt(i, tSize) { i := add(i, 1) } {
                    mstore(add(tP, mul(i, 32)), 0)
                }

                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    let ai := mload(add(aP, mul(i, 32)))

                    // ---- Multiply pass: accumulate a[i] * b into t ----
                    let carry := 0
                    for { let j := 0 } lt(j, kk) { j := add(j, 1) } {
                        let tOff := add(tP, mul(j, 32))
                        let tj := mload(tOff)
                        let bj := mload(add(bP, mul(j, 32)))

                        // (ab_hi, ab_lo) = ai * bj
                        let ab_lo := mul(ai, bj)
                        let mm := mulmod(ai, bj, not(0))
                        let ab_hi := sub(sub(mm, ab_lo), lt(mm, ab_lo))

                        // sum1 = ab_lo + tj
                        let sum1 := add(ab_lo, tj)
                        let c1 := lt(sum1, ab_lo)

                        // sum2 = sum1 + carry
                        let sum2 := add(sum1, carry)
                        let c2 := lt(sum2, sum1)

                        mstore(tOff, sum2)
                        carry := add(ab_hi, add(c1, c2))
                    }

                    // Propagate carry into t[k] and t[k+1]
                    let tkOff := add(tP, mul(kk, 32))
                    let tk := mload(tkOff)
                    let tkNew := add(tk, carry)
                    let c := lt(tkNew, tk)
                    mstore(tkOff, tkNew)

                    let tk1Off := add(tP, mul(add(kk, 1), 32))
                    mstore(tk1Off, add(mload(tk1Off), c))

                    // ---- Reduce pass: Montgomery reduction ----
                    let t0 := mload(tP)
                    let m := mul(t0, n0inv)

                    carry := 0
                    for { let j := 0 } lt(j, kk) { j := add(j, 1) } {
                        let tOff := add(tP, mul(j, 32))
                        let tj2 := mload(tOff)
                        let nj := mload(add(nP, mul(j, 32)))

                        // (mn_hi, mn_lo) = m * nj
                        let mn_lo := mul(m, nj)
                        let mm2 := mulmod(m, nj, not(0))
                        let mn_hi := sub(sub(mm2, mn_lo), lt(mm2, mn_lo))

                        // sum1 = mn_lo + tj2
                        let s1 := add(mn_lo, tj2)
                        let cc1 := lt(s1, mn_lo)

                        // sum2 = s1 + carry
                        let s2 := add(s1, carry)
                        let cc2 := lt(s2, s1)

                        // For j > 0, shift down: store in t[j-1]
                        if gt(j, 0) {
                            mstore(add(tP, mul(sub(j, 1), 32)), s2)
                        }
                        // For j == 0, s2 should be zero (by construction), we discard it

                        carry := add(mn_hi, add(cc1, cc2))
                    }

                    // After the reduce loop, handle upper limbs with shift
                    let tkVal := mload(add(tP, mul(kk, 32)))
                    let sum := add(tkVal, carry)
                    let overflow := lt(sum, tkVal)
                    mstore(add(tP, mul(sub(kk, 1), 32)), sum)

                    let tk1Val := mload(add(tP, mul(add(kk, 1), 32)))
                    mstore(add(tP, mul(kk, 32)), add(tk1Val, overflow))
                    mstore(add(tP, mul(add(kk, 1), 32)), 0)
                }

                // Final conditional subtraction: if t >= n, t = t - n
                // We check t[k] first (if non-zero, definitely >= n)
                // Then compare t[0..k-1] with n[0..k-1]
                let doSub := 0
                let tkFinal := mload(add(tP, mul(kk, 32)))
                if gt(tkFinal, 0) {
                    doSub := 1
                }
                if iszero(doSub) {
                    doSub := limbGte(tP, nP, kk)
                }

                // Copy t to result
                for { let i := 0 } lt(i, kk) { i := add(i, 1) } {
                    mstore(add(resP, mul(i, 32)), mload(add(tP, mul(i, 32))))
                }

                if doSub {
                    limbSub(resP, nP, kk)
                }
            }

            // ============================================================
            //  MAIN LOGIC
            // ============================================================

            let modPtr := modulus   // points to length field
            let modData := add(modulus, 0x20) // points to data
            let mLen := mload(modPtr)

            // Compute k = ceil(mLen / 32)
            let k := div(add(mLen, 31), 32)

            // Check modulus == 0 (all zeros) -> result is already zeros
            let modIsZero := 1
            {
                let mWords := div(mLen, 32)
                for { let i := 0 } lt(i, mWords) { i := add(i, 1) } {
                    if mload(add(modData, mul(i, 32))) {
                        modIsZero := 0
                        i := mWords // break
                    }
                }
                // Check remaining bytes
                let rem := mod(mLen, 32)
                if rem {
                    // Load the last partial word
                    let lastWord := mload(add(modData, sub(mLen, rem)))
                    // Mask to only the relevant bytes
                    let mask := sub(shl(mul(rem, 8), 1), 1)
                    // Actually for big-endian, the partial word is at the start
                    // Let me reconsider: if mLen = 33, k=2, first 1 byte is partial
                    // mload at modData reads first 32 bytes, then byte 33 is separate
                    // Actually mload at add(modData, 32) reads bytes 32..63 but only byte 32 exists
                    // This is tricky - let me just check all bytes
                }
            }
            // Simpler zero check
            {
                modIsZero := 1
                for { let i := 0 } lt(i, mLen) { i := add(i, 1) } {
                    if byte(0, mload(add(modData, i))) {
                        modIsZero := 0
                        i := mLen
                    }
                }
            }

            if iszero(modIsZero) {
                // Check if modulus == 1 (result is 0 for any input)
                let modIsOne := 0
                {
                    let allZeroExceptLast := 1
                    for { let i := 0 } lt(i, sub(mLen, 1)) { i := add(i, 1) } {
                        if byte(0, mload(add(modData, i))) {
                            allZeroExceptLast := 0
                            i := mLen
                        }
                    }
                    if allZeroExceptLast {
                        if eq(byte(0, mload(add(modData, sub(mLen, 1)))), 1) {
                            modIsOne := 1
                        }
                    }
                }

                if iszero(modIsOne) {
                    // ---- Allocate memory for limb arrays ----
                    let freeMemPtr := mload(0x40)
                    let nP := freeMemPtr                              // k limbs for modulus
                    let aP := add(nP, mul(k, 32))                    // k limbs for base (Montgomery form)
                    let rP := add(aP, mul(k, 32))                    // k limbs for result accumulator
                    let tP := add(rP, mul(k, 32))                    // (k+2) limbs for montMul scratch
                    let r2P := add(tP, mul(add(k, 2), 32))           // k limbs for R^2 mod n
                    let scratchP := add(r2P, mul(k, 32))             // k limbs scratch for montMul operand
                    let oneP := add(scratchP, mul(k, 32))            // k limbs for "1"
                    let endMem := add(oneP, mul(k, 32))
                    mstore(0x40, endMem)

                    // ---- Convert modulus bytes (big-endian) to little-endian limbs at nP ----
                    // Zero out nP first
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        mstore(add(nP, mul(i, 32)), 0)
                    }
                    // Copy limbs: limb 0 = last 32 bytes, limb 1 = next-to-last 32 bytes, etc.
                    {
                        let fullLimbs := div(mLen, 32)
                        for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                            // Limb i reads from offset (mLen - 32*(i+1)) in the byte array
                            let byteOffset := sub(mLen, mul(add(i, 1), 32))
                            let val := mload(add(modData, byteOffset))
                            mstore(add(nP, mul(i, 32)), val)
                        }
                        // Handle partial leading limb
                        let rem := mod(mLen, 32)
                        if rem {
                            // The topmost limb has only 'rem' bytes
                            // These are the first 'rem' bytes of modData
                            // Load 32 bytes starting at modData, but we only want the first 'rem' bytes
                            let raw := mload(modData)
                            // Shift right to keep only the first 'rem' bytes
                            let val := shr(mul(sub(32, rem), 8), raw)
                            mstore(add(nP, mul(fullLimbs, 32)), val)
                        }
                    }

                    // ---- Convert base bytes to limbs at aP (temporarily) ----
                    // Zero out aP
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        mstore(add(aP, mul(i, 32)), 0)
                    }
                    {
                        let bData := add(base, 0x20)
                        let bLen := mload(base)
                        let fullLimbs := div(bLen, 32)
                        // Only copy up to k limbs
                        let limbsToCopy := fullLimbs
                        if gt(limbsToCopy, k) { limbsToCopy := k }

                        for { let i := 0 } lt(i, limbsToCopy) { i := add(i, 1) } {
                            let byteOffset := sub(bLen, mul(add(i, 1), 32))
                            let val := mload(add(bData, byteOffset))
                            mstore(add(aP, mul(i, 32)), val)
                        }
                        // Handle partial leading limb (only if it fits within k limbs)
                        let rem := mod(bLen, 32)
                        if rem {
                            let limbIdx := fullLimbs
                            if lt(limbIdx, k) {
                                let raw := mload(bData)
                                let val := shr(mul(sub(32, rem), 8), raw)
                                mstore(add(aP, mul(limbIdx, 32)), val)
                            }
                        }
                    }

                    // ---- Reduce base mod n if base >= n ----
                    // We need base mod n. Easiest: use precompile for base^1 mod n
                    // Actually, let's just check if base >= n and subtract if needed
                    // For simplicity and correctness with arbitrary size bases, let's
                    // do base mod n using the precompile
                    // Actually we should just reduce properly. Let me use the precompile
                    // for base mod n (base^1 mod n) which handles all edge cases.
                    // But wait - that's what we're trying to compute in general. Let's
                    // just ensure we handle the case where base >= n. For Montgomery to
                    // work correctly, we need 0 <= a < n. If base >= n, we need to reduce.
                    // Simplest correct approach: call precompile to compute base mod n.
                    {
                        // Encode precompile call: base^1 mod n = base mod n
                        let baseLen := mload(base)
                        // We need: baseLen(32) | expLen=1(32) | modLen(32) | base(baseLen) | exp=1(1) | mod(mLen)
                        let inputLen := add(add(96, baseLen), add(1, mLen))
                        let inputP := mload(0x40)
                        mstore(0x40, add(inputP, inputLen))
                        mstore(inputP, baseLen)
                        mstore(add(inputP, 32), 1) // exp length = 1
                        mstore(add(inputP, 64), mLen) // mod length
                        // Copy base data
                        let src := add(base, 0x20)
                        let dst := add(inputP, 96)
                        for { let i := 0 } lt(i, baseLen) { i := add(i, 32) } {
                            mstore(add(dst, i), mload(add(src, i)))
                        }
                        // Write exponent = 1
                        mstore8(add(inputP, add(96, baseLen)), 1)
                        // Copy modulus data
                        dst := add(inputP, add(97, baseLen))
                        src := modData
                        for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                            mstore(add(dst, i), mload(add(src, i)))
                        }

                        // Allocate output buffer (mLen bytes)
                        let outP := mload(0x40)
                        mstore(0x40, add(outP, mLen))

                        let success := staticcall(gas(), 0x05, inputP, inputLen, outP, mLen)
                        if iszero(success) { revert(0, 0) }

                        // Convert output (big-endian bytes) to limbs at aP
                        for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                            mstore(add(aP, mul(i, 32)), 0)
                        }
                        {
                            let fullLimbs := div(mLen, 32)
                            for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                                let byteOffset := sub(mLen, mul(add(i, 1), 32))
                                let val := mload(add(outP, byteOffset))
                                mstore(add(aP, mul(i, 32)), val)
                            }
                            let rem := mod(mLen, 32)
                            if rem {
                                let raw := mload(outP)
                                let val := shr(mul(sub(32, rem), 8), raw)
                                mstore(add(aP, mul(fullLimbs, 32)), val)
                            }
                        }
                    }

                    // ---- Prepare "one" = 1 in limb form at oneP ----
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        mstore(add(oneP, mul(i, 32)), 0)
                    }
                    mstore(oneP, 1)

                    // ---- Compute Montgomery inverse n0inv ----
                    // We want n0inv such that n[0] * n0inv === type(uint256).max (i.e., -1 mod 2^256)
                    // Newton's method: inv = 1, then inv = inv * (2 - n[0] * inv) mod 2^256
                    // After 8 iterations, we have n[0] * inv === 1 mod 2^256
                    // Then n0inv = 0 - inv so that n[0] * n0inv === -1 mod 2^256
                    let n0 := mload(nP)
                    let inv := 1
                    for { let iter := 0 } lt(iter, 8) { iter := add(iter, 1) } {
                        inv := mul(inv, sub(2, mul(n0, inv)))
                    }
                    let n0inv := sub(0, inv)

                    // ---- Compute R^2 mod n using precompile ----
                    // R = 2^(256*k), R^2 = 2^(512*k)
                    // precompile: base=2, exp=512*k, mod=n
                    {
                        // Compute exponent = 512*k in big-endian bytes
                        // 512*k can be up to 512*128 = 65536, fits in 2 bytes typically
                        // But let's be safe and use 32 bytes for the exponent
                        let expVal := mul(512, k)

                        // Determine byte length of expVal
                        let expByteLen := 0
                        {
                            let tmp := expVal
                            for {} gt(tmp, 0) {} {
                                expByteLen := add(expByteLen, 1)
                                tmp := shr(8, tmp)
                            }
                            if iszero(expByteLen) { expByteLen := 1 }
                        }

                        // Input: baseLen=1(32) | expLen(32) | modLen(32) | base=2(1) | exp(expByteLen) | mod(mLen)
                        let inputLen := add(add(97, expByteLen), mLen)
                        let inputP := mload(0x40)
                        mstore(0x40, add(inputP, add(inputLen, 32))) // extra padding

                        mstore(inputP, 1) // base length = 1
                        mstore(add(inputP, 32), expByteLen) // exp length
                        mstore(add(inputP, 64), mLen) // mod length

                        // Base = 2
                        mstore8(add(inputP, 96), 2)

                        // Write exponent big-endian
                        {
                            let expOff := add(inputP, 97)
                            let tmp := expVal
                            // Write bytes from MSB to LSB
                            for { let b := 0 } lt(b, expByteLen) { b := add(b, 1) } {
                                let byteIdx := sub(sub(expByteLen, 1), b)
                                mstore8(add(expOff, byteIdx), and(tmp, 0xff))
                                tmp := shr(8, tmp)
                            }
                        }

                        // Copy modulus
                        let modOff := add(inputP, add(97, expByteLen))
                        for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                            mstore(add(modOff, i), mload(add(modData, i)))
                        }

                        // Output at r2P... but precompile returns big-endian bytes
                        let outP := mload(0x40)
                        mstore(0x40, add(outP, add(mLen, 32)))

                        let success := staticcall(gas(), 0x05, inputP, inputLen, outP, mLen)
                        if iszero(success) { revert(0, 0) }

                        // Convert output to limbs at r2P
                        for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                            mstore(add(r2P, mul(i, 32)), 0)
                        }
                        {
                            let fullLimbs := div(mLen, 32)
                            for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                                let byteOffset := sub(mLen, mul(add(i, 1), 32))
                                let val := mload(add(outP, byteOffset))
                                mstore(add(r2P, mul(i, 32)), val)
                            }
                            let rem := mod(mLen, 32)
                            if rem {
                                let raw := mload(outP)
                                let val := shr(mul(sub(32, rem), 8), raw)
                                mstore(add(r2P, mul(fullLimbs, 32)), val)
                            }
                        }
                    }

                    // ---- Convert base to Montgomery form ----
                    // a_mont = montMul(a, R^2, n, n0inv, k)
                    // Use scratchP temporarily to hold the result, then copy to aP
                    montMul(scratchP, aP, r2P, nP, tP, n0inv, k)
                    // Copy scratchP -> aP
                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                        mstore(add(aP, mul(i, 32)), mload(add(scratchP, mul(i, 32))))
                    }

                    // ---- Initialize result in Montgomery form ----
                    // result_mont = montMul(1, R^2, n, n0inv, k) = R mod n
                    montMul(rP, oneP, r2P, nP, tP, n0inv, k)

                    // ---- Square-and-multiply exponentiation ----
                    // Scan exponent bits from MSB to LSB
                    {
                        let expData := add(exponent, 0x20)
                        let expLen := mload(exponent)

                        // Find the first non-zero byte to know where to start
                        let startByte := 0
                        for {} lt(startByte, expLen) { startByte := add(startByte, 1) } {
                            if byte(0, mload(add(expData, startByte))) {
                                // Found first non-zero byte
                                break
                            }
                        }

                        if lt(startByte, expLen) {
                            // Get the first non-zero byte to find MSB
                            let firstByte := byte(0, mload(add(expData, startByte)))

                            // Find the highest set bit in firstByte
                            let topBit := 7
                            for {} gt(topBit, 0) {} {
                                if and(firstByte, shl(topBit, 1)) {
                                    break
                                }
                                topBit := sub(topBit, 1)
                            }

                            // Process the first byte starting from the bit below the MSB
                            // (the MSB itself just initializes - actually for standard
                            //  left-to-right binary, we skip the leading 1 since result
                            //  is already R mod n... wait, no.
                            //  Let me think: result starts as R mod n (= 1 in Montgomery form).
                            //  For each bit from MSB to LSB:
                            //    result = result^2
                            //    if bit == 1: result = result * base
                            //  But the very first bit is always 1 (since we start from MSB).
                            //  After squaring R mod n, we get R mod n.
                            //  Then multiply by a_mont: get a_mont.
                            //  That's correct for the leading 1 bit.
                            //  So we DO process every bit including the MSB.)

                            // Process first byte
                            {
                                // Start from topBit down to 0
                                let bit := topBit
                                for {} iszero(gt(bit, topBit)) {} {
                                    // Square
                                    montMul(scratchP, rP, rP, nP, tP, n0inv, k)
                                    // Copy scratchP -> rP
                                    for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                                        mstore(add(rP, mul(i, 32)), mload(add(scratchP, mul(i, 32))))
                                    }

                                    // If bit is set, multiply
                                    if and(firstByte, shl(bit, 1)) {
                                        montMul(scratchP, rP, aP, nP, tP, n0inv, k)
                                        for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                                            mstore(add(rP, mul(i, 32)), mload(add(scratchP, mul(i, 32))))
                                        }
                                    }

                                    if iszero(bit) { break }
                                    bit := sub(bit, 1)
                                }
                            }

                            // Process remaining bytes
                            {
                                let byteIdx := add(startByte, 1)
                                for {} lt(byteIdx, expLen) { byteIdx := add(byteIdx, 1) } {
                                    let b := byte(0, mload(add(expData, byteIdx)))

                                    // Process all 8 bits of this byte, MSB first
                                    let bit := 7
                                    for {} iszero(gt(bit, 7)) {} {
                                        // Square
                                        montMul(scratchP, rP, rP, nP, tP, n0inv, k)
                                        for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                                            mstore(add(rP, mul(i, 32)), mload(add(scratchP, mul(i, 32))))
                                        }

                                        // If bit is set, multiply
                                        if and(b, shl(bit, 1)) {
                                            montMul(scratchP, rP, aP, nP, tP, n0inv, k)
                                            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                                                mstore(add(rP, mul(i, 32)), mload(add(scratchP, mul(i, 32))))
                                            }
                                        }

                                        if iszero(bit) { break }
                                        bit := sub(bit, 1)
                                    }
                                }
                            }
                        }
                        // If exponent is all zero, result stays as R mod n.
                        // But x^0 mod n = 1 (for n > 1). R mod n in Montgomery form
                        // represents 1. After converting out, we get 1. That's correct.
                        // Wait... result_mont = R mod n represents the value 1 in Montgomery form.
                        // When we convert out: montMul(result_mont, 1) = R mod n * 1 * R^{-1} mod n = 1.
                        // Actually for exponent = 0: any base^0 = 1 mod n (for n > 1).
                        // Our result_mont starts as R mod n. Converting out gives 1. Correct!
                    }

                    // ---- Convert out of Montgomery form ----
                    // result = montMul(result_mont, 1, n, n0inv, k)
                    montMul(scratchP, rP, oneP, nP, tP, n0inv, k)

                    // ---- Convert limbs back to big-endian bytes in result ----
                    {
                        let resData := add(result, 0x20)
                        // Zero out result first
                        for { let i := 0 } lt(i, mLen) { i := add(i, 32) } {
                            mstore(add(resData, i), 0)
                        }

                        let fullLimbs := div(mLen, 32)
                        for { let i := 0 } lt(i, fullLimbs) { i := add(i, 1) } {
                            // Limb i goes to byte offset (mLen - 32*(i+1))
                            let byteOffset := sub(mLen, mul(add(i, 1), 32))
                            mstore(add(resData, byteOffset), mload(add(scratchP, mul(i, 32))))
                        }
                        // Handle partial leading limb
                        let rem := mod(mLen, 32)
                        if rem {
                            let limbVal := mload(add(scratchP, mul(fullLimbs, 32)))
                            // Write 'rem' bytes at the start of resData
                            // We need to write the low 'rem' bytes of limbVal
                            // into the first 'rem' bytes in big-endian order
                            // limbVal's bytes should go at positions 0..rem-1
                            // Shift left so the value is in the top 'rem' bytes of a 32-byte word
                            let shifted := shl(mul(sub(32, rem), 8), limbVal)
                            // Read existing 32 bytes at resData (which includes bytes we already wrote)
                            let existing := mload(resData)
                            // Mask: keep only the first 'rem' bytes from shifted, rest from existing
                            let mask := not(sub(shl(mul(sub(32, rem), 8), 1), 1))
                            mstore(resData, or(and(shifted, mask), and(existing, not(mask))))
                        }
                    }
                }
                // else modIsOne -> result is already zeros, which is correct
            }
            // else modIsZero -> result is already zeros, which is correct
        }
    }
}
