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

            // Rotations, the sigma functions and the round body are all written
            // out inline below rather than as Yul functions: at 6 rotations and
            // 2 sigmas per round, call overhead dominated the arithmetic.
            //
            // The rotations are also left unmasked. `or(shr(n,x), shl(32-n,x))`
            // leaves junk above bit 31, but every consumer either xors those
            // values together and masks once, or feeds them into an add whose
            // result is masked — and bits >= 32 of an addend cannot affect bits
            // < 32 of a sum. Inputs to a rotation must still be exactly 32 bits,
            // which holds for a, e and every W entry.

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
            // Zero the rest
            for { let j := dataLen } lt(j, paddedLen) { j := add(j, 0x20) } {
                mstore(add(padBuf, j), 0)
            }
            // 0x80 byte
            mstore8(add(padBuf, dataLen), 0x80)

            // 64-bit big-endian bit length at end
            mstore(add(padBuf, sub(paddedLen, 8)), shl(192, bitLen))

            // ── Allocate hash state, message schedule, round constants ──
            //   hPtr +    0 .. +  256   H[0..7]
            //   hPtr +  256 .. + 2304   W[0..63]
            //   hPtr + 2304 .. + 4352   K[0..63]
            // K sits exactly 2048 bytes above the matching W entry, so the round
            // loop reaches both from one live pointer (see the round loop below).
            let hPtr := mload(0x40)
            mstore(0x40, add(hPtr, 4352))

            // Initialize H[0..7]
            mstore(hPtr, 0x6a09e667)
            mstore(add(hPtr, 0x20), 0xbb67ae85)
            mstore(add(hPtr, 0x40), 0x3c6ef372)
            mstore(add(hPtr, 0x60), 0xa54ff53a)
            mstore(add(hPtr, 0x80), 0x510e527f)
            mstore(add(hPtr, 0xa0), 0x9b05688c)
            mstore(add(hPtr, 0xc0), 0x1f83d9ab)
            mstore(add(hPtr, 0xe0), 0x5be0cd19)

            // ── Round constants K[0..63] ─────────────────────────
            // Written once per hash() call and read with a single mload per
            // round. The previous 64-case `switch` compiled to a linear chain of
            // comparisons re-walked on every one of the 64 rounds of every block.
            {
                let k := add(hPtr, 2304)
                mstore(k,          0x428a2f98) mstore(add(k, 0x020), 0x71374491)
                mstore(add(k, 0x040), 0xb5c0fbcf) mstore(add(k, 0x060), 0xe9b5dba5)
                mstore(add(k, 0x080), 0x3956c25b) mstore(add(k, 0x0a0), 0x59f111f1)
                mstore(add(k, 0x0c0), 0x923f82a4) mstore(add(k, 0x0e0), 0xab1c5ed5)
                mstore(add(k, 0x100), 0xd807aa98) mstore(add(k, 0x120), 0x12835b01)
                mstore(add(k, 0x140), 0x243185be) mstore(add(k, 0x160), 0x550c7dc3)
                mstore(add(k, 0x180), 0x72be5d74) mstore(add(k, 0x1a0), 0x80deb1fe)
                mstore(add(k, 0x1c0), 0x9bdc06a7) mstore(add(k, 0x1e0), 0xc19bf174)
                mstore(add(k, 0x200), 0xe49b69c1) mstore(add(k, 0x220), 0xefbe4786)
                mstore(add(k, 0x240), 0x0fc19dc6) mstore(add(k, 0x260), 0x240ca1cc)
                mstore(add(k, 0x280), 0x2de92c6f) mstore(add(k, 0x2a0), 0x4a7484aa)
                mstore(add(k, 0x2c0), 0x5cb0a9dc) mstore(add(k, 0x2e0), 0x76f988da)
                mstore(add(k, 0x300), 0x983e5152) mstore(add(k, 0x320), 0xa831c66d)
                mstore(add(k, 0x340), 0xb00327c8) mstore(add(k, 0x360), 0xbf597fc7)
                mstore(add(k, 0x380), 0xc6e00bf3) mstore(add(k, 0x3a0), 0xd5a79147)
                mstore(add(k, 0x3c0), 0x06ca6351) mstore(add(k, 0x3e0), 0x14292967)
                mstore(add(k, 0x400), 0x27b70a85) mstore(add(k, 0x420), 0x2e1b2138)
                mstore(add(k, 0x440), 0x4d2c6dfc) mstore(add(k, 0x460), 0x53380d13)
                mstore(add(k, 0x480), 0x650a7354) mstore(add(k, 0x4a0), 0x766a0abb)
                mstore(add(k, 0x4c0), 0x81c2c92e) mstore(add(k, 0x4e0), 0x92722c85)
                mstore(add(k, 0x500), 0xa2bfe8a1) mstore(add(k, 0x520), 0xa81a664b)
                mstore(add(k, 0x540), 0xc24b8b70) mstore(add(k, 0x560), 0xc76c51a3)
                mstore(add(k, 0x580), 0xd192e819) mstore(add(k, 0x5a0), 0xd6990624)
                mstore(add(k, 0x5c0), 0xf40e3585) mstore(add(k, 0x5e0), 0x106aa070)
                mstore(add(k, 0x600), 0x19a4c116) mstore(add(k, 0x620), 0x1e376c08)
                mstore(add(k, 0x640), 0x2748774c) mstore(add(k, 0x660), 0x34b0bcb5)
                mstore(add(k, 0x680), 0x391c0cb3) mstore(add(k, 0x6a0), 0x4ed8aa4a)
                mstore(add(k, 0x6c0), 0x5b9cca4f) mstore(add(k, 0x6e0), 0x682e6ff3)
                mstore(add(k, 0x700), 0x748f82ee) mstore(add(k, 0x720), 0x78a5636f)
                mstore(add(k, 0x740), 0x84c87814) mstore(add(k, 0x760), 0x8cc70208)
                mstore(add(k, 0x780), 0x90befffa) mstore(add(k, 0x7a0), 0xa4506ceb)
                mstore(add(k, 0x7c0), 0xbef9a3f7) mstore(add(k, 0x7e0), 0xc67178f2)
            }

            // ── Process each 64-byte block ───────────────────────
            // padBuf walks forward one block at a time; paddedLen counts down.
            for {} gt(paddedLen, 0) { paddedLen := sub(paddedLen, 64) padBuf := add(padBuf, 64) } {
                let wPtr := add(hPtr, 256)

                // Prepare W[0..15] from block (big-endian 32-bit words).
                // Two walking pointers rather than mul-indexing: the source
                // advances 4 bytes per word, the destination one 32-byte slot.
                {
                    let src := padBuf
                    let dst := wPtr
                    let wEnd := add(wPtr, 512) // 16 slots
                    for {} lt(dst, wEnd) { dst := add(dst, 0x20) src := add(src, 4) } {
                        mstore(dst, shr(224, mload(src)))
                    }
                }

                // W[16..63]. One walking pointer; the four back-references sit at
                // fixed byte offsets below it (t-2 => -64, t-7 => -224,
                // t-15 => -480, t-16 => -512), so each is a single sub.
                {
                    let p := add(wPtr, 512)     // &W[16]
                    let wEnd := add(wPtr, 2048) // &W[64]
                    for {} lt(p, wEnd) { p := add(p, 0x20) } {
                        let x2 := mload(sub(p, 64))   // W[t-2]
                        let x15 := mload(sub(p, 480)) // W[t-15]
                        // sigma1(x2) = ROTR17 ^ ROTR19 ^ SHR10
                        let s1w := xor(xor(
                            or(shr(17, x2), shl(15, x2)),
                            or(shr(19, x2), shl(13, x2))),
                            shr(10, x2))
                        // sigma0(x15) = ROTR7 ^ ROTR18 ^ SHR3
                        let s0w := xor(xor(
                            or(shr(7, x15), shl(25, x15)),
                            or(shr(18, x15), shl(14, x15))),
                            shr(3, x15))
                        mstore(p, and(add(add(add(
                            s1w,
                            mload(sub(p, 224))),
                            s0w),
                            mload(sub(p, 512))), MASK32))
                    }
                }

                // Initialize working state from H (at wPtr-256 .. wPtr-32)
                let a := mload(sub(wPtr, 256))
                let b := mload(sub(wPtr, 224))
                let c := mload(sub(wPtr, 192))
                let dd := mload(sub(wPtr, 160))
                let e := mload(sub(wPtr, 128))
                let ff := mload(sub(wPtr, 96))
                let gg := mload(sub(wPtr, 64))
                // h lives in scratch memory (0x00): keeping it on the stack
                // pushes hPtr out of reach of the round loop's swap depth.
                mstore(0x00, mload(sub(wPtr, 32)))

                // 64 rounds — state kept in stack locals.
                // `wp` walks W[0..63]; the matching K[t] is a fixed 2048 bytes
                // above it, so one live pointer serves both and the round loop
                // adds no net stack slot over the previous `t` counter.
                //
                // The masks dropped below are redundant, not missing: a..gg are
                // maintained <= 2^32-1, rotr32 masks its own result, and and/xor
                // of 32-bit values stays 32-bit. Only the adds can carry past
                // bit 31, so only they are masked.
                for { let wp := wPtr } lt(wp, add(wPtr, 2048)) { wp := add(wp, 0x20) } {
                    // Sigma1(e) = ROTR6 ^ ROTR11 ^ ROTR25
                    let s1 := xor(xor(
                        or(shr(6, e), shl(26, e)),
                        or(shr(11, e), shl(21, e))),
                        or(shr(25, e), shl(7, e)))
                    let ch := xor(and(e, ff), and(not(e), gg))
                    let t1 := and(
                        add(add(add(add(mload(0x00), s1), ch), mload(add(wp, 2048))), mload(wp)),
                        MASK32
                    )

                    // Sigma0(a) = ROTR2 ^ ROTR13 ^ ROTR22
                    let s0 := xor(xor(
                        or(shr(2, a), shl(30, a)),
                        or(shr(13, a), shl(19, a))),
                        or(shr(22, a), shl(10, a)))
                    let mj := xor(xor(and(a, b), and(a, c)), and(b, c))
                    let t2 := and(add(s0, mj), MASK32)

                    mstore(0x00, gg)
                    gg := ff
                    ff := e
                    e := and(add(dd, t1), MASK32)
                    dd := c
                    c := b
                    b := a
                    a := and(add(t1, t2), MASK32)
                }

                // H[i] += working[i]
                mstore(sub(wPtr, 256), and(add(mload(sub(wPtr, 256)), a), MASK32))
                mstore(sub(wPtr, 224), and(add(mload(sub(wPtr, 224)), b), MASK32))
                mstore(sub(wPtr, 192), and(add(mload(sub(wPtr, 192)), c), MASK32))
                mstore(sub(wPtr, 160), and(add(mload(sub(wPtr, 160)), dd), MASK32))
                mstore(sub(wPtr, 128), and(add(mload(sub(wPtr, 128)), e), MASK32))
                mstore(sub(wPtr, 96), and(add(mload(sub(wPtr, 96)), ff), MASK32))
                mstore(sub(wPtr, 64), and(add(mload(sub(wPtr, 64)), gg), MASK32))
                mstore(sub(wPtr, 32), and(add(mload(sub(wPtr, 32)), mload(0x00)), MASK32))
            }

            // ── Produce 32-byte result (big-endian) ──────────────
            let h0 := mload(add(hPtr, 0x0))
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
