// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Modexp} from "../../src/modexp/Modexp.sol";
import {ModexpBarrett} from "../../src/modexp/ModexpBarrett.sol";

contract ModexpRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return Modexp.modexp(base, exponent, modulus);
    }
}

contract BarrettRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return ModexpBarrett.modexp(base, exponent, modulus);
    }
}

/// @title ModexpLeanVectorsTest
/// @notice Stress tests ported from Lean modexp test vectors, targeting specific
///         edge cases in the Montgomery and Barrett implementations.
///         Uses the EVM modexp precompile (0x05) as the oracle for expected values.
contract ModexpLeanVectorsTest is Test {
    ModexpRunner modexpRunner;
    BarrettRunner barrettRunner;

    function setUp() public {
        modexpRunner = new ModexpRunner();
        barrettRunner = new BarrettRunner();
    }

    // ── Precompile oracle ────────────────────────────────────────────────

    function _evmModexp(bytes memory base, bytes memory exp, bytes memory mod_)
        internal view returns (bytes memory)
    {
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exp.length), uint256(mod_.length), base, exp, mod_
        );
        bytes memory result = new bytes(mod_.length);
        assembly {
            let ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(result, 0x20), mload(mod_))
            if iszero(ok) { revert(0, 0) }
        }
        return result;
    }

    // ── Big number helpers ───────────────────────────────────────────────

    /// @dev Encode a uint256 as minimal big-endian bytes (no leading zeros).
    function _toMinBytes(uint256 val) internal pure returns (bytes memory) {
        if (val == 0) return hex"00";
        uint256 byteLen;
        uint256 tmp = val;
        while (tmp > 0) { byteLen++; tmp >>= 8; }
        bytes memory result = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            result[byteLen - 1 - i] = bytes1(uint8(val));
            val >>= 8;
        }
        return result;
    }

    /// @dev Build a big-endian bytes representation of 2^n (a 1 followed by zero bytes).
    function _pow2Bytes(uint256 n) internal pure returns (bytes memory) {
        require(n % 8 == 0, "pow2Bytes: n must be multiple of 8 for exact byte boundary");
        uint256 totalBytes = n / 8 + 1;
        bytes memory result = new bytes(totalBytes);
        result[0] = 0x01;
        return result;
    }

    /// @dev Build a big-endian representation of (2^n - offset) where offset is small.
    ///      n must be a multiple of 8.
    function _pow2MinusSmall(uint256 n, uint256 offset) internal pure returns (bytes memory) {
        require(n % 8 == 0, "pow2MinusSmall: n must be multiple of 8");
        uint256 totalBytes = n / 8;
        if (offset == 0) {
            bytes memory r2 = new bytes(totalBytes + 1);
            r2[0] = 0x01;
            return r2;
        }
        bytes memory result = new bytes(totalBytes);
        // Start with all 0xFF (= 2^n - 1), then subtract (offset - 1)
        for (uint256 i = 0; i < totalBytes; i++) {
            result[i] = 0xFF;
        }
        uint256 sub_ = offset - 1;
        for (uint256 i = totalBytes; i > 0 && sub_ > 0;) {
            i--;
            uint256 cur = uint8(result[i]);
            uint256 digit = sub_ & 0xFF;
            if (cur >= digit) {
                result[i] = bytes1(uint8(cur - digit));
                sub_ >>= 8;
            } else {
                result[i] = bytes1(uint8(256 + cur - digit));
                sub_ = (sub_ >> 8) + 1;
            }
        }
        return result;
    }

    /// @dev Build a big-endian representation of (2^n + offset) where offset is small.
    function _pow2PlusSmall(uint256 n, uint256 offset) internal pure returns (bytes memory) {
        require(n % 8 == 0, "pow2PlusSmall: n must be multiple of 8");
        uint256 totalBytes = n / 8 + 1;
        bytes memory result = new bytes(totalBytes);
        result[0] = 0x01;
        // Add offset to the least significant bytes
        uint256 carry = offset;
        for (uint256 i = totalBytes; i > 0 && carry > 0;) {
            i--;
            uint256 val = uint8(result[i]) + (carry & 0xFF);
            result[i] = bytes1(uint8(val & 0xFF));
            carry = (carry >> 8) + (val >> 8);
        }
        return result;
    }

    /// @dev Pads bytes to exactly `len` bytes (left-pads with zeros).
    function _padTo(bytes memory b, uint256 len) internal pure returns (bytes memory) {
        if (b.length >= len) return b;
        bytes memory result = new bytes(len);
        uint256 offset = len - b.length;
        for (uint256 i = 0; i < b.length; i++) {
            result[offset + i] = b[i];
        }
        return result;
    }

    // ── Differential assertion helper ────────────────────────────────────

    function _assertModexp(
        string memory name,
        bytes memory base,
        bytes memory exp,
        bytes memory mod_
    ) internal view {
        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, name);
    }

    function _assertBarrett(
        string memory name,
        bytes memory base,
        bytes memory exp,
        bytes memory mod_
    ) internal view {
        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = barrettRunner.run(base, exp, mod_);
        assertEq(actual, expected, name);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 1. Power-of-2 moduli (Barrett path)
    // ══════════════════════════════════════════════════════════════════════

    function test_pow2_3_pow_10_mod_16() public view {
        _assertBarrett("3^10 mod 16", hex"03", hex"0a", hex"10");
    }

    function test_pow2_3_pow_10_mod_256() public view {
        _assertBarrett("3^10 mod 256", hex"03", hex"0a", hex"0100");
    }

    function test_pow2_7_pow_100_mod_2p32() public view {
        _assertBarrett("7^100 mod 2^32", hex"07", hex"64", hex"0100000000");
    }

    function test_pow2_3_pow_100_mod_2p256() public view {
        bytes memory mod_ = _pow2Bytes(256);
        _assertBarrett("3^100 mod 2^256", hex"03", hex"64", mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 2. Even moduli near 2^256 (Barrett edge)
    // ══════════════════════════════════════════════════════════════════════

    function test_even_near_2p256_minus_2() public view {
        bytes memory mod_ = _pow2MinusSmall(256, 2);
        _assertModexp("3^100 mod (2^256 - 2)", hex"03", hex"64", mod_);
    }

    function test_even_near_2p256_plus_2() public view {
        bytes memory mod_ = _pow2PlusSmall(256, 2);
        _assertModexp("3^100 mod (2^256 + 2)", hex"03", hex"64", mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 3. base = modulus - 1 (Montgomery final subtraction)
    // ══════════════════════════════════════════════════════════════════════

    function test_mont_final_sub_2p256m1() public view {
        // (2^256 - 2)^2 mod (2^256 - 1) = 1
        bytes memory mod_ = _pow2MinusSmall(256, 1); // 2^256 - 1
        bytes memory base = _pow2MinusSmall(256, 2);  // 2^256 - 2
        _assertModexp("(2^256-2)^2 mod (2^256-1)", base, hex"02", mod_);
    }

    function test_mont_final_sub_17() public view {
        // 16^2 mod 17 = 1
        _assertModexp("16^2 mod 17", hex"10", hex"02", hex"11");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 4. Non-32-byte-aligned moduli (limb conversion)
    // ══════════════════════════════════════════════════════════════════════

    function test_limb_33byte_modulus() public view {
        // 42^1000 mod (2^264 - 7)
        bytes memory mod_ = _pow2MinusSmall(264, 7);
        bytes memory exp = _toMinBytes(1000);
        _assertModexp("42^1000 mod (2^264 - 7)", hex"2a", exp, mod_);
    }

    function test_limb_48byte_modulus() public view {
        // (2^300)^100 mod (2^384 - 5) = 2^30000 mod (2^384 - 5)
        bytes memory mod_ = _pow2MinusSmall(384, 5);
        bytes memory exp = _toMinBytes(30000);
        _assertModexp("2^30000 mod (2^384 - 5)", hex"02", exp, mod_);
    }

    function test_limb_31byte_modulus() public view {
        // 7^100 mod (2^248 - 1)
        bytes memory mod_ = _pow2MinusSmall(248, 1);
        _assertModexp("7^100 mod (2^248 - 1)", hex"07", hex"64", mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 5. Result = 0 cases (final subtraction when t == n)
    // ══════════════════════════════════════════════════════════════════════

    function test_result_zero_2p256_mod_2p128() public view {
        // 2^256 mod 2^128 = 0
        bytes memory base = _pow2Bytes(256);
        bytes memory mod_ = _pow2Bytes(128);
        _assertModexp("2^256 mod 2^128", base, hex"01", mod_);
    }

    function test_result_zero_2p256_sq_mod_2p256() public view {
        // (2^256)^2 mod 2^256 = 0
        bytes memory base = _pow2Bytes(256);
        bytes memory mod_ = _pow2Bytes(256);
        _assertModexp("(2^256)^2 mod 2^256", base, hex"02", mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 6. Montgomery n0inv edge (low limb patterns)
    // ══════════════════════════════════════════════════════════════════════

    function test_n0inv_all_ones() public view {
        // 7^50 mod (2^256 - 1) — low limb = 0xFFF...F
        bytes memory mod_ = _pow2MinusSmall(256, 1);
        _assertModexp("7^50 mod (2^256 - 1)", hex"07", hex"32", mod_);
    }

    function test_n0inv_specific_pattern() public view {
        // 5^50 mod (2^128 + 1) — specific n0inv pattern
        bytes memory mod_ = _pow2PlusSmall(128, 1);
        _assertModexp("5^50 mod (2^128 + 1)", hex"05", hex"32", mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 7. Dispatcher odd/even
    // ══════════════════════════════════════════════════════════════════════

    function test_dispatch_odd_0xFF01() public view {
        // 3^10 mod 0xFF01 (odd)
        _assertModexp("3^10 mod 0xFF01 (odd)", hex"03", hex"0a", hex"FF01");
    }

    function test_dispatch_even_0xFF00() public view {
        // 3^10 mod 0xFF00 (even)
        _assertModexp("3^10 mod 0xFF00 (even)", hex"03", hex"0a", hex"FF00");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 8. RSA-sized (1024-bit, 2048-bit)
    // ══════════════════════════════════════════════════════════════════════

    function test_rsa1024_montgomery() public view {
        // 17^500 mod (2^1024 - 1) — 4-limb Montgomery (odd modulus)
        bytes memory mod_ = _pow2MinusSmall(1024, 1);
        bytes memory exp = _toMinBytes(500);
        _assertModexp("17^500 mod (2^1024 - 1)", hex"11", exp, mod_);
    }

    function test_rsa1024_barrett() public view {
        // 17^500 mod (2^1024 - 2) — 4-limb Barrett (even modulus)
        bytes memory mod_ = _pow2MinusSmall(1024, 2);
        bytes memory exp = _toMinBytes(500);
        _assertModexp("17^500 mod (2^1024 - 2)", hex"11", exp, mod_);
    }

    function test_rsa2048_montgomery() public view {
        // 3^1000 mod (2^2048 - 1) — 8-limb Montgomery
        bytes memory mod_ = _pow2MinusSmall(2048, 1);
        bytes memory exp = _toMinBytes(1000);
        _assertModexp("3^1000 mod (2^2048 - 1)", hex"03", exp, mod_);
    }

    // ══════════════════════════════════════════════════════════════════════
    // 9. Barrett correction / Knuth D edges
    // ══════════════════════════════════════════════════════════════════════

    function test_barrett_norm_shift_zero() public view {
        // 5^100 mod (2^255 + 2) — even, normalization shift = 0
        // 2^255 + 2: top bit of the 32-byte value is set, so shift = 0
        // Build: 0x80...02 (32 bytes)
        bytes memory mod_ = new bytes(32);
        mod_[0] = 0x80;
        mod_[31] = 0x02;
        _assertModexp("5^100 mod (2^255 + 2)", hex"05", hex"64", mod_);
    }

    function test_barrett_large_norm_shift() public view {
        // 5^100 mod (2^257 + 2) — even, large normalization shift
        // 2^257 + 2: 0x02 followed by 32 zero bytes, last byte = 0x02
        bytes memory mod_ = new bytes(33);
        mod_[0] = 0x02;
        mod_[32] = 0x02;
        _assertModexp("5^100 mod (2^257 + 2)", hex"05", hex"64", mod_);
    }
}
