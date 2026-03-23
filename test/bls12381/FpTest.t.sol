// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Fp} from "../../src/bls12381/Fp.sol";
import {LimbMath} from "../../src/modexp/LimbMath.sol";

contract FpTest is Test {
    // p as individual components for convenience
    // p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    bytes constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    // ── test_add_basic: 7 + 11 = 18 ─────────────────────────────

    function test_add_basic() public pure {
        bytes memory a = Fp.fromUint256(7);
        bytes memory b = Fp.fromUint256(11);
        bytes memory result = Fp.add(a, b);
        bytes memory expected = Fp.fromUint256(18);
        assertTrue(Fp.eq(result, expected), "7 + 11 should equal 18");
    }

    // ── test_add_wraps: (p-1) + 2 = 1 mod p ────────────────────

    function test_add_wraps() public pure {
        bytes memory pMinus1 = Fp.neg(Fp.fromUint256(1));
        bytes memory two = Fp.fromUint256(2);
        bytes memory result = Fp.add(pMinus1, two);
        bytes memory expected = Fp.fromUint256(1);
        assertTrue(Fp.eq(result, expected), "(p-1) + 2 should equal 1 mod p");
    }

    // ── test_mul_basic: 7 * 6 = 42 ─────────────────────────────

    function test_mul_basic() public pure {
        bytes memory a = Fp.fromUint256(7);
        bytes memory b = Fp.fromUint256(6);
        bytes memory result = Fp.mul(a, b);
        bytes memory expected = Fp.fromUint256(42);
        assertTrue(Fp.eq(result, expected), "7 * 6 should equal 42");
    }

    // ── test_mul_large: a * b * inv(b) == a ─────────────────────

    function test_mul_large() public pure {
        bytes memory a = Fp.fromUint256(0xdeadbeefdeadbeefdeadbeefdeadbeef);
        bytes memory b = Fp.fromUint256(0xcafebabecafebabecafebabecafebabe);
        bytes memory ab = Fp.mul(a, b);
        bytes memory abDivB = Fp.mul(ab, Fp.inv(b));
        assertTrue(Fp.eq(abDivB, a), "a * b * inv(b) should equal a");
    }

    // ── test_neg: neg(1) = p - 1 ───────────────────────────────

    function test_neg() public pure {
        bytes memory one = Fp.fromUint256(1);
        bytes memory result = Fp.neg(one);
        // p - 1
        bytes memory expected =
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa";
        assertTrue(Fp.eq(result, expected), "neg(1) should equal p - 1");
    }

    // ── test_neg_zero: neg(0) = 0 ──────────────────────────────

    function test_neg_zero() public pure {
        bytes memory zero = Fp.fromUint256(0);
        bytes memory result = Fp.neg(zero);
        bytes memory expected = Fp.fromUint256(0);
        assertTrue(Fp.eq(result, expected), "neg(0) should equal 0");
    }

    // ── test_sub: 10 - 3 = 7 ───────────────────────────────────

    function test_sub() public pure {
        bytes memory a = Fp.fromUint256(10);
        bytes memory b = Fp.fromUint256(3);
        bytes memory result = Fp.sub(a, b);
        bytes memory expected = Fp.fromUint256(7);
        assertTrue(Fp.eq(result, expected), "10 - 3 should equal 7");
    }

    // ── test_inv: 7 * inv(7) = 1 ───────────────────────────────

    function test_inv() public pure {
        bytes memory seven = Fp.fromUint256(7);
        bytes memory sevenInv = Fp.inv(seven);
        bytes memory result = Fp.mul(seven, sevenInv);
        bytes memory one = Fp.fromUint256(1);
        assertTrue(Fp.eq(result, one), "7 * inv(7) should equal 1");
    }

    // ── test_sqrt: sqrt(4)^2 = 4 ───────────────────────────────

    function test_sqrt() public pure {
        bytes memory four = Fp.fromUint256(4);
        bytes memory root = Fp.sqrt(four);
        bytes memory result = Fp.sqr(root);
        assertTrue(Fp.eq(result, four), "sqrt(4)^2 should equal 4");
    }

    // ── test_isSquare_true: isSquare(4) = true ──────────────────

    function test_isSquare_true() public pure {
        bytes memory four = Fp.fromUint256(4);
        assertTrue(Fp.isSquare(four), "4 should be a quadratic residue");
    }

    // ── test_isSquare_false: isSquare(p-1) = false ──────────────

    function test_isSquare_false() public pure {
        // p - 1 = -1 mod p. Since p = 3 mod 4, -1 is not a QR.
        bytes memory pMinus1 = Fp.neg(Fp.fromUint256(1));
        assertFalse(Fp.isSquare(pMinus1), "p-1 should not be a quadratic residue");
    }

    // ── test_sgn0: sgn0(3) = 1, sgn0(4) = 0 ───────────────────

    function test_sgn0() public pure {
        bytes memory three = Fp.fromUint256(3);
        bytes memory four = Fp.fromUint256(4);
        assertEq(Fp.sgn0(three), 1, "sgn0(3) should be 1 (odd)");
        assertEq(Fp.sgn0(four), 0, "sgn0(4) should be 0 (even)");
    }

    // ── test_fromUint256: correct 48-byte encoding ──────────────

    function test_fromUint256() public pure {
        bytes memory result = Fp.fromUint256(0x1234);
        assertEq(result.length, 48, "fromUint256 should produce 48 bytes");
        // First 16 bytes should be zero (padding)
        for (uint256 i = 0; i < 16; i++) {
            assertEq(uint8(result[i]), 0, "leading bytes should be zero");
        }
        // Last two bytes should be 0x12, 0x34
        assertEq(uint8(result[46]), 0x12, "byte 46 should be 0x12");
        assertEq(uint8(result[47]), 0x34, "byte 47 should be 0x34");
    }

    // ── test_eq: eq(fromUint256(42), fromUint256(42)) = true ────

    function test_eq() public pure {
        bytes memory a = Fp.fromUint256(42);
        bytes memory b = Fp.fromUint256(42);
        assertTrue(Fp.eq(a, b), "equal values should be equal");
        bytes memory c = Fp.fromUint256(43);
        assertFalse(Fp.eq(a, c), "different values should not be equal");
    }

    // ── test_verify_pLimbs: hardcoded limbs match bytesToLimbs ──

    function test_verify_pLimbs() public pure {
        uint256[] memory fromBytes = LimbMath.bytesToLimbs(P, 2);
        // Expected hardcoded values from Fp._pLimbs()
        uint256 expectedLimb0 = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
        uint256 expectedLimb1 = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
        assertEq(fromBytes[0], expectedLimb0, "limb 0 mismatch");
        assertEq(fromBytes[1], expectedLimb1, "limb 1 mismatch");
    }
}
