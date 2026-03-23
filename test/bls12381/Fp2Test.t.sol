// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Fp} from "../../src/bls12381/Fp.sol";
import {Fp2} from "../../src/bls12381/Fp2.sol";

contract Fp2Test is Test {
    // ── test_add: (1+2i) + (3+4i) = (4+6i) ─────────────────────

    function test_add() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(1), Fp.fromUint256(2));
        Fp2.Element memory b = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        Fp2.Element memory result = Fp2.add(a, b);
        Fp2.Element memory expected = Fp2.fromFp(Fp.fromUint256(4), Fp.fromUint256(6));
        assertTrue(Fp2.eq(result, expected), "(1+2i) + (3+4i) should equal (4+6i)");
    }

    // ── test_sub: (5+7i) - (2+3i) = (3+4i) ─────────────────────

    function test_sub() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(5), Fp.fromUint256(7));
        Fp2.Element memory b = Fp2.fromFp(Fp.fromUint256(2), Fp.fromUint256(3));
        Fp2.Element memory result = Fp2.sub(a, b);
        Fp2.Element memory expected = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        assertTrue(Fp2.eq(result, expected), "(5+7i) - (2+3i) should equal (3+4i)");
    }

    // ── test_mul: (2+3i)(4+5i) = -7 + 22i ──────────────────────

    function test_mul() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(2), Fp.fromUint256(3));
        Fp2.Element memory b = Fp2.fromFp(Fp.fromUint256(4), Fp.fromUint256(5));
        Fp2.Element memory result = Fp2.mul(a, b);
        // -7 mod p = p - 7
        Fp2.Element memory expected = Fp2.fromFp(Fp.neg(Fp.fromUint256(7)), Fp.fromUint256(22));
        assertTrue(Fp2.eq(result, expected), "(2+3i)(4+5i) should equal (-7+22i)");
    }

    // ── test_sqr: (3+4i)^2 = -7 + 24i ──────────────────────────

    function test_sqr() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        Fp2.Element memory result = Fp2.sqr(a);
        Fp2.Element memory expected = Fp2.fromFp(Fp.neg(Fp.fromUint256(7)), Fp.fromUint256(24));
        assertTrue(Fp2.eq(result, expected), "(3+4i)^2 should equal (-7+24i)");
    }

    // ── test_inv: a * inv(a) = 1 for a = (3+4i) ────────────────

    function test_inv() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        Fp2.Element memory aInv = Fp2.inv(a);
        Fp2.Element memory result = Fp2.mul(a, aInv);
        Fp2.Element memory expected = Fp2.one();
        assertTrue(Fp2.eq(result, expected), "(3+4i) * inv(3+4i) should equal 1");
    }

    // ── test_neg: -(1+2i) = (p-1, p-2) ─────────────────────────

    function test_neg() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(1), Fp.fromUint256(2));
        Fp2.Element memory result = Fp2.neg(a);
        Fp2.Element memory expected = Fp2.fromFp(Fp.neg(Fp.fromUint256(1)), Fp.neg(Fp.fromUint256(2)));
        assertTrue(Fp2.eq(result, expected), "-(1+2i) should equal (p-1, p-2)");
    }

    // ── test_mulByI: i*(3+4i) = -4 + 3i ────────────────────────

    function test_mulByI() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        Fp2.Element memory result = Fp2.mulByI(a);
        Fp2.Element memory expected = Fp2.fromFp(Fp.neg(Fp.fromUint256(4)), Fp.fromUint256(3));
        assertTrue(Fp2.eq(result, expected), "i*(3+4i) should equal (-4+3i)");
    }

    // ── test_conjugate: conj(3+4i) = (3, -4) ───────────────────

    function test_conjugate() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(3), Fp.fromUint256(4));
        Fp2.Element memory result = Fp2.conjugate(a);
        Fp2.Element memory expected = Fp2.fromFp(Fp.fromUint256(3), Fp.neg(Fp.fromUint256(4)));
        assertTrue(Fp2.eq(result, expected), "conj(3+4i) should equal (3,-4)");
    }

    // ── test_sqrt: sqrt(4+0i) should exist and verify ───────────

    function test_sqrt() public pure {
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(4), new bytes(48));
        (bool exists, Fp2.Element memory root) = Fp2.sqrt(a);
        assertTrue(exists, "sqrt(4+0i) should exist");
        Fp2.Element memory check = Fp2.sqr(root);
        assertTrue(Fp2.eq(check, a), "sqrt(4+0i)^2 should equal (4+0i)");
    }

    // ── test_sgn0: verify behavior per RFC 9380 ─────────────────

    function test_sgn0() public pure {
        // sgn0(0+0i) = 0 (both components zero, both even)
        Fp2.Element memory zeroElem = Fp2.zero();
        assertEq(Fp2.sgn0(zeroElem), 0, "sgn0(0+0i) should be 0");

        // sgn0(1+0i): c0=1 is odd => sign0=1 => result=1
        Fp2.Element memory a = Fp2.fromFp(Fp.fromUint256(1), new bytes(48));
        assertEq(Fp2.sgn0(a), 1, "sgn0(1+0i) should be 1");

        // sgn0(2+0i): c0=2 is even, nonzero => sign0=0, zero0=0 => result=0
        Fp2.Element memory b = Fp2.fromFp(Fp.fromUint256(2), new bytes(48));
        assertEq(Fp2.sgn0(b), 0, "sgn0(2+0i) should be 0");

        // sgn0(0+1i): c0=0 => zero0=1, sign1=sgn0(1)=1 => result=0|1=1
        Fp2.Element memory c = Fp2.fromFp(new bytes(48), Fp.fromUint256(1));
        assertEq(Fp2.sgn0(c), 1, "sgn0(0+1i) should be 1");

        // sgn0(0+2i): c0=0 => zero0=1, sign1=sgn0(2)=0 => result=0|0=0
        Fp2.Element memory d = Fp2.fromFp(new bytes(48), Fp.fromUint256(2));
        assertEq(Fp2.sgn0(d), 0, "sgn0(0+2i) should be 0");

        // sgn0(2+1i): c0=2 even nonzero => sign0=0, zero0=0 => result=0
        Fp2.Element memory e = Fp2.fromFp(Fp.fromUint256(2), Fp.fromUint256(1));
        assertEq(Fp2.sgn0(e), 0, "sgn0(2+1i) should be 0");

        // sgn0(1+2i): c0=1 odd => sign0=1 => result=1
        Fp2.Element memory f = Fp2.fromFp(Fp.fromUint256(1), Fp.fromUint256(2));
        assertEq(Fp2.sgn0(f), 1, "sgn0(1+2i) should be 1");
    }
}
