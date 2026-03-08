// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title Sha256
/// @notice Pure Solidity implementation of SHA-256 (FIPS 180-4).
/// @dev Assembly-optimized. All arithmetic is 32-bit, big-endian.
///      Hash state stored in memory to avoid stack-too-deep.
library Sha256 {
    /// @notice Computes the SHA-256 hash of the input data.
    /// @param data The input data to hash.
    /// @return result The 32-byte SHA-256 digest.
    function hash(bytes memory data) internal pure returns (bytes32 result) {
        assembly {
            let MASK32 := 0xffffffff

            // ── Round constants K[0..63] ─────────────────────────
            function getK(i) -> k {
                switch i
                case  0 { k := 0x428a2f98 } case  1 { k := 0x71374491 }
                case  2 { k := 0xb5c0fbcf } case  3 { k := 0xe9b5dba5 }
                case  4 { k := 0x3956c25b } case  5 { k := 0x59f111f1 }
                case  6 { k := 0x923f82a4 } case  7 { k := 0xab1c5ed5 }
                case  8 { k := 0xd807aa98 } case  9 { k := 0x12835b01 }
                case 10 { k := 0x243185be } case 11 { k := 0x550c7dc3 }
                case 12 { k := 0x72be5d74 } case 13 { k := 0x80deb1fe }
                case 14 { k := 0x9bdc06a7 } case 15 { k := 0xc19bf174 }
                case 16 { k := 0xe49b69c1 } case 17 { k := 0xefbe4786 }
                case 18 { k := 0x0fc19dc6 } case 19 { k := 0x240ca1cc }
                case 20 { k := 0x2de92c6f } case 21 { k := 0x4a7484aa }
                case 22 { k := 0x5cb0a9dc } case 23 { k := 0x76f988da }
                case 24 { k := 0x983e5152 } case 25 { k := 0xa831c66d }
                case 26 { k := 0xb00327c8 } case 27 { k := 0xbf597fc7 }
                case 28 { k := 0xc6e00bf3 } case 29 { k := 0xd5a79147 }
                case 30 { k := 0x06ca6351 } case 31 { k := 0x14292967 }
                case 32 { k := 0x27b70a85 } case 33 { k := 0x2e1b2138 }
                case 34 { k := 0x4d2c6dfc } case 35 { k := 0x53380d13 }
                case 36 { k := 0x650a7354 } case 37 { k := 0x766a0abb }
                case 38 { k := 0x81c2c92e } case 39 { k := 0x92722c85 }
                case 40 { k := 0xa2bfe8a1 } case 41 { k := 0xa81a664b }
                case 42 { k := 0xc24b8b70 } case 43 { k := 0xc76c51a3 }
                case 44 { k := 0xd192e819 } case 45 { k := 0xd6990624 }
                case 46 { k := 0xf40e3585 } case 47 { k := 0x106aa070 }
                case 48 { k := 0x19a4c116 } case 49 { k := 0x1e376c08 }
                case 50 { k := 0x2748774c } case 51 { k := 0x34b0bcb5 }
                case 52 { k := 0x391c0cb3 } case 53 { k := 0x4ed8aa4a }
                case 54 { k := 0x5b9cca4f } case 55 { k := 0x682e6ff3 }
                case 56 { k := 0x748f82ee } case 57 { k := 0x78a5636f }
                case 58 { k := 0x84c87814 } case 59 { k := 0x8cc70208 }
                case 60 { k := 0x90befffa } case 61 { k := 0xa4506ceb }
                case 62 { k := 0xbef9a3f7 } case 63 { k := 0xc67178f2 }
            }

            // ── SHA-256 functions ────────────────────────────────
            function rotr32(x, n) -> r {
                r := and(or(shr(n, x), shl(sub(32, n), x)), 0xffffffff)
            }

            // sha256Round is inlined below to avoid memory load/store per round

            // ── Padding ──────────────────────────────────────────
            let dataLen := mload(data)
            let dataPtr := add(data, 0x20)
            let bitLen := mul(dataLen, 8)
            let paddedLen := and(add(add(dataLen, 9), 63), not(63))

            // Allocate padded buffer
            let padBuf := mload(0x40)
            mstore(0x40, add(padBuf, paddedLen))

            // Copy data
            mcopy(padBuf, dataPtr, dataLen)
            let i := dataLen
            // Zero the rest
            for { let j := i } lt(j, paddedLen) { j := add(j, 0x20) } {
                mstore(add(padBuf, j), 0)
            }
            // 0x80 byte
            mstore8(add(padBuf, dataLen), 0x80)

            // 64-bit big-endian bit length at end
            mstore(add(padBuf, sub(paddedLen, 8)), shl(192, bitLen))

            // ── Allocate hash state H[0..7] and message schedule in memory ──
            let hPtr := mload(0x40)              // 8 words * 32 bytes = 256 bytes
            let wPtr := add(hPtr, 256)            // 64 words * 32 bytes = 2048 bytes
            mstore(0x40, add(wPtr, 2048))

            // Initialize H[0..7]
            mstore(hPtr, 0x6a09e667)
            mstore(add(hPtr, 0x20), 0xbb67ae85)
            mstore(add(hPtr, 0x40), 0x3c6ef372)
            mstore(add(hPtr, 0x60), 0xa54ff53a)
            mstore(add(hPtr, 0x80), 0x510e527f)
            mstore(add(hPtr, 0xa0), 0x9b05688c)
            mstore(add(hPtr, 0xc0), 0x1f83d9ab)
            mstore(add(hPtr, 0xe0), 0x5be0cd19)

            // message schedule helper: sigma0
            function smallSigma0(x) -> r {
                r := and(xor(xor(rotr32(x, 7), rotr32(x, 18)), shr(3, x)), 0xffffffff)
            }
            function smallSigma1(x) -> r {
                r := and(xor(xor(rotr32(x, 17), rotr32(x, 19)), shr(10, x)), 0xffffffff)
            }

            // ── Process each 64-byte block ───────────────────────
            let numBlocks := div(paddedLen, 64)
            for { let blk := 0 } lt(blk, numBlocks) { blk := add(blk, 1) } {
                let blockPtr := add(padBuf, mul(blk, 64))

                // Prepare W[0..15] from block (big-endian 32-bit words)
                for { let t := 0 } lt(t, 16) { t := add(t, 1) } {
                    let off := add(blockPtr, mul(t, 4))
                    mstore(add(wPtr, mul(t, 0x20)), shr(224, mload(off)))
                }

                // W[16..63]
                for { let t := 16 } lt(t, 64) { t := add(t, 1) } {
                    let wt2  := mload(add(wPtr, mul(sub(t, 2), 0x20)))
                    let wt7  := mload(add(wPtr, mul(sub(t, 7), 0x20)))
                    let wt15 := mload(add(wPtr, mul(sub(t, 15), 0x20)))
                    let wt16 := mload(add(wPtr, mul(sub(t, 16), 0x20)))
                    mstore(add(wPtr, mul(t, 0x20)),
                        and(add(add(add(smallSigma1(wt2), wt7), smallSigma0(wt15)), wt16), MASK32))
                }

                // Initialize working state from H
                let a := mload(hPtr)
                let b := mload(add(hPtr, 0x20))
                let c := mload(add(hPtr, 0x40))
                let dd := mload(add(hPtr, 0x60))
                let e := mload(add(hPtr, 0x80))
                let ff := mload(add(hPtr, 0xa0))
                let gg := mload(add(hPtr, 0xc0))
                let hh := mload(add(hPtr, 0xe0))

                // 64 rounds — state kept in stack locals
                for { let t := 0 } lt(t, 64) { t := add(t, 1) } {
                    let s1 := and(xor(xor(rotr32(e, 6), rotr32(e, 11)), rotr32(e, 25)), MASK32)
                    let ch := and(xor(and(e, ff), and(not(e), gg)), MASK32)
                    let wt := mload(add(wPtr, mul(t, 0x20)))
                    let t1 := and(add(add(add(add(hh, s1), ch), getK(t)), wt), MASK32)

                    let s0 := and(xor(xor(rotr32(a, 2), rotr32(a, 13)), rotr32(a, 22)), MASK32)
                    let mj := and(xor(xor(and(a, b), and(a, c)), and(b, c)), MASK32)
                    let t2 := and(add(s0, mj), MASK32)

                    hh := gg
                    gg := ff
                    ff := e
                    e := and(add(dd, t1), MASK32)
                    dd := c
                    c := b
                    b := a
                    a := and(add(t1, t2), MASK32)
                }

                // H[i] += working[i]
                mstore(hPtr, and(add(mload(hPtr), a), MASK32))
                mstore(add(hPtr, 0x20), and(add(mload(add(hPtr, 0x20)), b), MASK32))
                mstore(add(hPtr, 0x40), and(add(mload(add(hPtr, 0x40)), c), MASK32))
                mstore(add(hPtr, 0x60), and(add(mload(add(hPtr, 0x60)), dd), MASK32))
                mstore(add(hPtr, 0x80), and(add(mload(add(hPtr, 0x80)), e), MASK32))
                mstore(add(hPtr, 0xa0), and(add(mload(add(hPtr, 0xa0)), ff), MASK32))
                mstore(add(hPtr, 0xc0), and(add(mload(add(hPtr, 0xc0)), gg), MASK32))
                mstore(add(hPtr, 0xe0), and(add(mload(add(hPtr, 0xe0)), hh), MASK32))
            }

            // ── Produce 32-byte result (big-endian) ──────────────
            let h0 := mload(hPtr)
            let h1 := mload(add(hPtr, 0x20))
            let h2 := mload(add(hPtr, 0x40))
            let h3 := mload(add(hPtr, 0x60))
            let h4 := mload(add(hPtr, 0x80))
            let h5 := mload(add(hPtr, 0xa0))
            let h6 := mload(add(hPtr, 0xc0))
            let h7 := mload(add(hPtr, 0xe0))

            result := or(shl(224, h0), or(shl(192, h1), or(shl(160, h2), or(shl(128, h3),
                     or(shl(96, h4), or(shl(64, h5), or(shl(32, h6), h7)))))))
        }
    }
}
