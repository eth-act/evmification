// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title ModexpPow2
/// @notice Modular exponentiation with power-of-2 moduli (base^exp mod 2^kBits).
library ModexpPow2 {
    /// @notice Computes base^exponent mod 2^kBits.
    /// @param base The base value (big-endian bytes).
    /// @param exponent The exponent value (big-endian bytes).
    /// @param kBits The exponent of the power-of-2 modulus.
    /// @return result The result (big-endian bytes, length ceil(kBits/8)).
    function modexp(bytes memory base, bytes memory exponent, uint256 kBits)
        internal pure returns (bytes memory result)
    {
        uint256 resultLen = (kBits + 7) / 8;

        // Edge case: kBits == 0 → modulus is 1, result is always 0 (empty bytes)
        if (kBits == 0) return new bytes(0);

        uint256 kLimbs = (kBits + 255) / 256;

        // Find first non-zero exponent byte (also detects zero exponent)
        uint256 expLen = exponent.length;
        uint256 expStart = 0;
        while (expStart < expLen && exponent[expStart] == 0) {
            expStart++;
        }

        // Zero exponent → result is 1
        if (expStart == expLen) {
            result = new bytes(resultLen);
            result[resultLen - 1] = 0x01;
            return result;
        }

        // Check if base is zero → result is 0
        bool baseIsZero = true;
        for (uint256 i = 0; i < base.length; i++) {
            if (base[i] != 0) { baseIsZero = false; break; }
        }
        if (baseIsZero) {
            return new bytes(resultLen);
        }

        // Convert base to limbs and truncate to kBits
        uint256[] memory a = _bytesToLimbs(base, kLimbs);
        _truncate(a, kBits, kLimbs);

        // Initialize result r = 1
        uint256[] memory r = new uint256[](kLimbs);
        r[0] = 1;

        // Exponentiation loop (left-to-right square-and-multiply)
        r = _modexpLoop(r, a, exponent, expStart, kBits, kLimbs);

        // Convert limbs back to bytes
        result = new bytes(resultLen);
        _limbsToBytes(r, result, resultLen);
    }

    // ── Limb conversion ──────────────────────────────────────────────

    /// @dev Converts big-endian bytes to a little-endian uint256[] limb array.
    ///      limbs[0] is the least significant 256-bit word.
    function _bytesToLimbs(bytes memory data, uint256 k) private pure returns (uint256[] memory limbs) {
        limbs = new uint256[](k);
        uint256 dataLen = data.length;
        uint256 fullLimbs = dataLen / 32;

        // Read full 32-byte words from the tail (least significant first)
        for (uint256 i = 0; i < fullLimbs; i++) {
            if (i >= k) break;
            uint256 offset = dataLen - (i + 1) * 32;
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(i, 0x20)),
                    mload(add(add(data, 0x20), offset))
                )
            }
        }

        // Handle a partial most-significant limb
        uint256 rem = dataLen % 32;
        if (rem > 0 && fullLimbs < k) {
            assembly {
                mstore(
                    add(add(limbs, 0x20), mul(fullLimbs, 0x20)),
                    shr(mul(sub(32, rem), 8), mload(add(data, 0x20)))
                )
            }
        }
    }

    /// @dev Converts a little-endian uint256[] limb array to big-endian bytes.
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

    // ── Truncation ───────────────────────────────────────────────────

    /// @dev Mask the top limb so only kBits % 256 bits survive.
    ///      No-op if kBits is a multiple of 256.
    function _truncate(uint256[] memory limbs, uint256 kBits, uint256 kLimbs) private pure {
        uint256 topBits = kBits % 256;
        if (topBits != 0) {
            uint256 mask = (1 << topBits) - 1;
            limbs[kLimbs - 1] &= mask;
        }
    }

    // ── Low multiply ─────────────────────────────────────────────────

    /// @dev Schoolbook multiply keeping only the bottom kLimbs limbs.
    function _lowMul(
        uint256[] memory a,
        uint256[] memory b,
        uint256 kLimbs
    ) private pure returns (uint256[] memory res) {
        res = new uint256[](kLimbs);
        assembly {
            let resBase := add(res, 0x20)
            let aBase := add(a, 0x20)
            let bBase := add(b, 0x20)
            let maxVal := not(0)

            for { let i := 0 } lt(i, kLimbs) { i := add(i, 1) } {
                let ai := mload(add(aBase, mul(i, 0x20)))
                if iszero(ai) { continue }

                let carry := 0
                let jLimit := sub(kLimbs, i)

                for { let j := 0 } lt(j, jLimit) { j := add(j, 1) } {
                    let bj := mload(add(bBase, mul(j, 0x20)))
                    let pos := add(i, j)
                    let resPtr := add(resBase, mul(pos, 0x20))

                    // 512-bit product: hi:lo = ai * bj
                    let lo := mul(ai, bj)
                    let mm := mulmod(ai, bj, maxVal)
                    let hi := sub(sub(mm, lo), lt(mm, lo))

                    // Add lo + carry + existing
                    let existing := mload(resPtr)
                    let s1 := add(existing, lo)
                    let c1 := lt(s1, existing)
                    let s2 := add(s1, carry)
                    let c2 := lt(s2, s1)

                    mstore(resPtr, s2)

                    // New carry = hi + c1 + c2
                    carry := add(hi, add(c1, c2))
                }
                // carry above kLimbs is discarded
            }
        }
    }

    // ── Copy limbs ───────────────────────────────────────────────────

    /// @dev Copy `len` limbs from `src` into `dst` (in-place overwrite).
    function _copyLimbs(uint256[] memory src, uint256[] memory dst, uint256 len) private pure {
        assembly {
            mcopy(add(dst, 0x20), add(src, 0x20), mul(len, 0x20))
        }
    }

    // ── Exponentiation loop ──────────────────────────────────────────

    /// @dev Left-to-right binary square-and-multiply with truncated low multiplication.
    /// @param startByte Index of the first non-zero exponent byte (caller pre-scanned).
    function _modexpLoop(
        uint256[] memory r,
        uint256[] memory a,
        bytes memory exponent,
        uint256 startByte,
        uint256 kBits,
        uint256 kLimbs
    ) private pure returns (uint256[] memory) {
        uint256 expLen = exponent.length;

        // Find the topmost set bit in the first non-zero byte
        uint8 b = uint8(exponent[startByte]);
        uint256 topBit = 7;
        while (topBit > 0 && (b >> topBit) & 1 == 0) {
            topBit--;
        }

        // Save free memory pointer for recycling
        uint256 freeMemBase;
        assembly { freeMemBase := mload(0x40) }

        // Unified loop
        bool started = false;
        for (uint256 byteIdx = startByte; byteIdx < expLen; byteIdx++) {
            b = uint8(exponent[byteIdx]);
            uint256 highBit = started ? 7 : topBit;
            started = true;
            for (uint256 bit = highBit + 1; bit > 0;) {
                unchecked { bit--; }

                // Square: r = lowMul(r, r) truncated
                assembly { mstore(0x40, freeMemBase) }
                uint256[] memory sq = _lowMul(r, r, kLimbs);
                _truncate(sq, kBits, kLimbs);
                _copyLimbs(sq, r, kLimbs);

                // Multiply if bit is set
                if ((b >> bit) & 1 == 1) {
                    assembly { mstore(0x40, freeMemBase) }
                    uint256[] memory prod = _lowMul(r, a, kLimbs);
                    _truncate(prod, kBits, kLimbs);
                    _copyLimbs(prod, r, kLimbs);
                }
            }
        }

        return r;
    }
}
