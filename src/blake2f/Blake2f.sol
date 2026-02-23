// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Blake2f
/// @notice Pure Solidity implementation of the BLAKE2b F compression function (EIP-152).
/// @dev Assembly-optimized. Working vector uses 32-byte stride matching Solidity array layout.
library Blake2f {
    /// @notice Computes the BLAKE2b F compression function.
    /// @param rounds Number of rounds (0..2^32-1).
    /// @param h State vector (8 uint64 values).
    /// @param m Message block (16 uint64 values).
    /// @param t Offset counters (2 uint64 values).
    /// @param finalBlock True if this is the final block.
    /// @return result The updated state vector (8 uint64 values).
    function compress(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) internal pure returns (uint64[8] memory result) {
        assembly {
            let MASK64 := 0xffffffffffffffff

            // ── IV constants ──────────────────────────────
            // BLAKE2b initialization vectors
            let iv0 := 0x6a09e667f3bcc908
            let iv1 := 0xbb67ae8584caa73b
            let iv2 := 0x3c6ef372fe94f82b
            let iv3 := 0xa54ff53a5f1d36f1
            let iv4 := 0x510e527fade682d1
            let iv5 := 0x9b05688c2b3e6c1f
            let iv6 := 0x1f83d9abfb41bd6b
            let iv7 := 0x5be0cd19137e2179

            // ── Sigma table (10 rows, packed as uint64: 16 nibbles each) ──
            // Each row encodes 16 indices (0-15) as 4-bit nibbles, MSB first.
            // sigma[r][j] = (sigmaRow >> (60 - j*4)) & 0xf
            function sigmaRow(r) -> s {
                switch r
                case 0 { s := 0x0123456789abcdef }
                case 1 { s := 0xea489fd61c02b753 }
                case 2 { s := 0xb8c052fdae367194 }
                case 3 { s := 0x7931dcbe265a40f8 }
                case 4 { s := 0x905724afe1bc683d }
                case 5 { s := 0x2c6a0b834d75fe19 }
                case 6 { s := 0xc51fed4a0763928b }
                case 7 { s := 0xdb7ec13950f4862a }
                case 8 { s := 0x6fe9b308c2d714a5 }
                case 9 { s := 0xa2847615fb9e3cd0 }
                default { revert(0, 0) }
            }

            // ── Allocate working vector v[0..15] in memory (32-byte stride) ──
            let vPtr := mload(0x40)
            mstore(0x40, add(vPtr, 512)) // 16 * 32 bytes

            // v[0..7] = h[0..7]
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(add(vPtr, mul(i, 0x20)), and(mload(add(h, mul(i, 0x20))), MASK64))
            }

            // v[8..15] = IV[0..7]
            mstore(add(vPtr, mul(8, 0x20)), iv0)
            mstore(add(vPtr, mul(9, 0x20)), iv1)
            mstore(add(vPtr, mul(10, 0x20)), iv2)
            mstore(add(vPtr, mul(11, 0x20)), iv3)
            mstore(add(vPtr, mul(12, 0x20)), iv4)
            mstore(add(vPtr, mul(13, 0x20)), iv5)
            mstore(add(vPtr, mul(14, 0x20)), iv6)
            mstore(add(vPtr, mul(15, 0x20)), iv7)

            // v[12] ^= t[0], v[13] ^= t[1]
            let t0 := and(mload(t), MASK64)
            let t1 := and(mload(add(t, 0x20)), MASK64)
            mstore(add(vPtr, mul(12, 0x20)), xor(mload(add(vPtr, mul(12, 0x20))), t0))
            mstore(add(vPtr, mul(13, 0x20)), xor(mload(add(vPtr, mul(13, 0x20))), t1))

            // if finalBlock: v[14] ^= 0xFFFFFFFFFFFFFFFF
            if finalBlock {
                mstore(add(vPtr, mul(14, 0x20)), xor(mload(add(vPtr, mul(14, 0x20))), MASK64))
            }

            // ── Rounds ──────────────────────────────────
            for { let r := 0 } lt(r, rounds) { r := add(r, 1) } {
                let sr := sigmaRow(mod(r, 10))

                // Helper: extract sigma index and load message word
                // sigma[j] = (sr >> (60 - j*4)) & 0xf
                // m[sigma[j]] is at m + sigma[j]*32

                // Column step
                // G(v, 0, 4, 8, 12, m[sigma[0]], m[sigma[1]])
                {
                    let s0 := and(shr(60, sr), 0xf)
                    let s1 := and(shr(56, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := vPtr
                    let bOff := add(vPtr, mul(4, 0x20))
                    let cOff := add(vPtr, mul(8, 0x20))
                    let dOff := add(vPtr, mul(12, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    // va = va + vb + x
                    va := and(add(add(va, vb), x), MASK64)
                    // vd = rotr64(vd ^ va, 32)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    // vc = vc + vd
                    vc := and(add(vc, vd), MASK64)
                    // vb = rotr64(vb ^ vc, 24)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    // va = va + vb + y
                    va := and(add(add(va, vb), y), MASK64)
                    // vd = rotr64(vd ^ va, 16)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    // vc = vc + vd
                    vc := and(add(vc, vd), MASK64)
                    // vb = rotr64(vb ^ vc, 63)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 1, 5, 9, 13, m[sigma[2]], m[sigma[3]])
                {
                    let s0 := and(shr(52, sr), 0xf)
                    let s1 := and(shr(48, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(1, 0x20))
                    let bOff := add(vPtr, mul(5, 0x20))
                    let cOff := add(vPtr, mul(9, 0x20))
                    let dOff := add(vPtr, mul(13, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 2, 6, 10, 14, m[sigma[4]], m[sigma[5]])
                {
                    let s0 := and(shr(44, sr), 0xf)
                    let s1 := and(shr(40, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(2, 0x20))
                    let bOff := add(vPtr, mul(6, 0x20))
                    let cOff := add(vPtr, mul(10, 0x20))
                    let dOff := add(vPtr, mul(14, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 3, 7, 11, 15, m[sigma[6]], m[sigma[7]])
                {
                    let s0 := and(shr(36, sr), 0xf)
                    let s1 := and(shr(32, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(3, 0x20))
                    let bOff := add(vPtr, mul(7, 0x20))
                    let cOff := add(vPtr, mul(11, 0x20))
                    let dOff := add(vPtr, mul(15, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }

                // Diagonal step
                // G(v, 0, 5, 10, 15, m[sigma[8]], m[sigma[9]])
                {
                    let s0 := and(shr(28, sr), 0xf)
                    let s1 := and(shr(24, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := vPtr
                    let bOff := add(vPtr, mul(5, 0x20))
                    let cOff := add(vPtr, mul(10, 0x20))
                    let dOff := add(vPtr, mul(15, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 1, 6, 11, 12, m[sigma[10]], m[sigma[11]])
                {
                    let s0 := and(shr(20, sr), 0xf)
                    let s1 := and(shr(16, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(1, 0x20))
                    let bOff := add(vPtr, mul(6, 0x20))
                    let cOff := add(vPtr, mul(11, 0x20))
                    let dOff := add(vPtr, mul(12, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 2, 7, 8, 13, m[sigma[12]], m[sigma[13]])
                {
                    let s0 := and(shr(12, sr), 0xf)
                    let s1 := and(shr(8, sr), 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(2, 0x20))
                    let bOff := add(vPtr, mul(7, 0x20))
                    let cOff := add(vPtr, mul(8, 0x20))
                    let dOff := add(vPtr, mul(13, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
                // G(v, 3, 4, 9, 14, m[sigma[14]], m[sigma[15]])
                {
                    let s0 := and(shr(4, sr), 0xf)
                    let s1 := and(sr, 0xf)
                    let x := and(mload(add(m, mul(s0, 0x20))), MASK64)
                    let y := and(mload(add(m, mul(s1, 0x20))), MASK64)
                    let aOff := add(vPtr, mul(3, 0x20))
                    let bOff := add(vPtr, mul(4, 0x20))
                    let cOff := add(vPtr, mul(9, 0x20))
                    let dOff := add(vPtr, mul(14, 0x20))
                    let va := mload(aOff)
                    let vb := mload(bOff)
                    let vc := mload(cOff)
                    let vd := mload(dOff)
                    va := and(add(add(va, vb), x), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(32, vd), shl(32, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(24, vb), shl(40, vb)), MASK64)
                    va := and(add(add(va, vb), y), MASK64)
                    vd := xor(vd, va)
                    vd := and(or(shr(16, vd), shl(48, vd)), MASK64)
                    vc := and(add(vc, vd), MASK64)
                    vb := xor(vb, vc)
                    vb := and(or(shr(63, vb), shl(1, vb)), MASK64)
                    mstore(aOff, va) mstore(bOff, vb) mstore(cOff, vc) mstore(dOff, vd)
                }
            }

            // Finalize: result[i] = h[i] ^ v[i] ^ v[i+8]
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let hi := and(mload(add(h, mul(i, 0x20))), MASK64)
                let vi := mload(add(vPtr, mul(i, 0x20)))
                let vi8 := mload(add(vPtr, mul(add(i, 8), 0x20)))
                mstore(add(result, mul(i, 0x20)), and(xor(xor(hi, vi), vi8), MASK64))
            }
        }
    }

    /// @notice Computes the BLAKE2b F compression function from raw 213-byte EIP-152 input.
    /// @param input 213 bytes in EIP-152 format.
    /// @return output 64 bytes of output.
    function compress(bytes memory input) internal pure returns (bytes memory output) {
        require(input.length == 213, "Blake2f: invalid input length");

        uint32 rounds;
        uint64[8] memory h;
        uint64[16] memory m;
        uint64[2] memory t;
        bool finalBlock;

        assembly {
            let ptr := add(input, 0x20)

            function swap64(x) -> r {
                x := and(x, 0xffffffffffffffff)
                x := or(shl(8, and(x, 0x00FF00FF00FF00FF)), shr(8, and(x, 0xFF00FF00FF00FF00)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                r := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
            }

            // Parse rounds (4 bytes big-endian)
            rounds := shr(224, mload(ptr))

            // Parse h[0..7] (8 little-endian uint64s starting at offset 4)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let off := add(ptr, add(4, mul(i, 8)))
                let val := shr(192, mload(off))
                mstore(add(h, mul(i, 0x20)), swap64(val))
            }

            // Parse m[0..15] (16 little-endian uint64s starting at offset 68)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let off := add(ptr, add(68, mul(i, 8)))
                let val := shr(192, mload(off))
                mstore(add(m, mul(i, 0x20)), swap64(val))
            }

            // Parse t[0..1] (2 little-endian uint64s starting at offset 196)
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                let off := add(ptr, add(196, mul(i, 8)))
                let val := shr(192, mload(off))
                mstore(add(t, mul(i, 0x20)), swap64(val))
            }

            // Parse finalBlock (1 byte at offset 212)
            finalBlock := shr(248, mload(add(ptr, 212)))
        }

        uint64[8] memory res = compress(rounds, h, m, t, finalBlock);

        // Encode output as 64 bytes (8 little-endian uint64s)
        output = new bytes(64);
        assembly {
            function swap64out(x) -> r {
                x := and(x, 0xffffffffffffffff)
                x := or(shl(8, and(x, 0x00FF00FF00FF00FF)), shr(8, and(x, 0xFF00FF00FF00FF00)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                r := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
            }

            let outPtr := add(output, 0x20)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let val := swap64out(mload(add(res, mul(i, 0x20))))
                // Write 8 LE bytes at outPtr + i*8
                // Store as big-endian in top 8 bytes then shift
                let shifted := shl(192, val)
                // We need to write exactly 8 bytes at the right position
                // Use mstore to write 32 bytes and rely on subsequent writes to overwrite
                mstore(add(outPtr, mul(i, 8)), shifted)
            }
        }
    }
}
