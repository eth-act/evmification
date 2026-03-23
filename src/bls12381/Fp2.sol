// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "./Fp.sol";

/// @title Fp2
/// @notice Quadratic extension field Fp2 = Fp[i]/(i^2 + 1) arithmetic.
/// @dev An Fp2 element is (c0, c1) representing c0 + c1*i where i^2 = -1.
///      Each component is a 48-byte big-endian `bytes memory` Fp element.
library Fp2 {
    struct Element {
        bytes c0; // real part
        bytes c1; // imaginary part
    }

    // ── Constructors ──────────────────────────────────────────────────

    /// @notice Returns the zero element (0, 0).
    function zero() internal pure returns (Element memory) {
        return Element(new bytes(48), new bytes(48));
    }

    /// @notice Returns the one element (1, 0).
    function one() internal pure returns (Element memory) {
        return Element(Fp.fromUint256(1), new bytes(48));
    }

    /// @notice Construct an Fp2 element from two Fp elements.
    function fromFp(bytes memory c0, bytes memory c1) internal pure returns (Element memory) {
        return Element(c0, c1);
    }

    // ── Arithmetic ────────────────────────────────────────────────────

    /// @notice (a + b) in Fp2.
    function add(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp.add(a.c0, b.c0), Fp.add(a.c1, b.c1));
    }

    /// @notice (a - b) in Fp2.
    function sub(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp.sub(a.c0, b.c0), Fp.sub(a.c1, b.c1));
    }

    /// @notice -a in Fp2.
    function neg(Element memory a) internal pure returns (Element memory) {
        return Element(Fp.neg(a.c0), Fp.neg(a.c1));
    }

    /// @notice (a * b) in Fp2 using Karatsuba.
    /// @dev 3 Fp muls instead of 4:
    ///      v0 = a0*b0, v1 = a1*b1
    ///      c0 = v0 - v1
    ///      c1 = (a0+a1)*(b0+b1) - v0 - v1
    function mul(Element memory a, Element memory b) internal pure returns (Element memory) {
        bytes memory v0 = Fp.mul(a.c0, b.c0);
        bytes memory v1 = Fp.mul(a.c1, b.c1);
        bytes memory c1 = Fp.sub(
            Fp.mul(Fp.add(a.c0, a.c1), Fp.add(b.c0, b.c1)),
            Fp.add(v0, v1)
        );
        return Element(Fp.sub(v0, v1), c1);
    }

    /// @notice a^2 in Fp2 using Karatsuba optimization.
    /// @dev (a0 + a1*i)^2 = (a0+a1)(a0-a1) + 2*a0*a1*i
    function sqr(Element memory a) internal pure returns (Element memory) {
        bytes memory c0 = Fp.mul(Fp.add(a.c0, a.c1), Fp.sub(a.c0, a.c1));
        bytes memory c1 = Fp.mul(a.c0, a.c1);
        c1 = Fp.add(c1, c1); // 2 * a0 * a1
        return Element(c0, c1);
    }

    /// @notice a^{-1} in Fp2.
    /// @dev (a0 + a1*i)^{-1} = (a0 - a1*i) / (a0^2 + a1^2)
    function inv(Element memory a) internal pure returns (Element memory) {
        bytes memory norm = Fp.add(Fp.sqr(a.c0), Fp.sqr(a.c1));
        bytes memory normInv = Fp.inv(norm);
        return Element(Fp.mul(a.c0, normInv), Fp.mul(Fp.neg(a.c1), normInv));
    }

    /// @notice Scalar multiplication by an Fp element.
    function mulFp(Element memory a, bytes memory s) internal pure returns (Element memory) {
        return Element(Fp.mul(a.c0, s), Fp.mul(a.c1, s));
    }

    // ── Predicates ────────────────────────────────────────────────────

    /// @notice Returns true if a == (0, 0).
    function isZero(Element memory a) internal pure returns (bool) {
        return Fp.isZero(a.c0) && Fp.isZero(a.c1);
    }

    /// @notice Returns true if a == b.
    function eq(Element memory a, Element memory b) internal pure returns (bool) {
        return Fp.eq(a.c0, b.c0) && Fp.eq(a.c1, b.c1);
    }

    /// @notice sgn0 per RFC 9380 Section 4.1 for m=2.
    /// @dev sign_0 = sgn0(c0) if c0 != 0 and c0 is odd, else
    ///      if c0 is zero return sgn0(c1), else (c0 even nonzero) return 0.
    function sgn0(Element memory a) internal pure returns (uint256) {
        uint256 sign0 = Fp.sgn0(a.c0);
        uint256 zero0 = Fp.isZero(a.c0) ? 1 : 0;
        uint256 sign1 = Fp.sgn0(a.c1);
        // sign_0 = sign0 OR (zero0 AND sign1)
        return sign0 | (zero0 & sign1);
    }

    // ── Square root ───────────────────────────────────────────────────

    /// @dev inv(2) mod p = (p+1)/2, precomputed.
    bytes constant INV_TWO = hex"0d0088f51cbff34d258dd3db21a5d66bb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd556";

    /// @notice Square root in Fp2.
    /// @return exists True if a is a quadratic residue in Fp2.
    /// @return root The square root if it exists.
    function sqrt(Element memory a) internal pure returns (bool exists, Element memory root) {
        if (isZero(a)) {
            return (true, zero());
        }

        // norm = c0^2 + c1^2 in Fp
        bytes memory norm = Fp.add(Fp.sqr(a.c0), Fp.sqr(a.c1));

        // t = sqrt(norm) in Fp; if not a QR, no sqrt in Fp2
        bytes memory t = Fp.sqrt(norm);
        if (!Fp.eq(Fp.sqr(t), norm)) {
            return (false, zero());
        }

        // Try x0 = sqrt((c0 + t) / 2)
        bytes memory twoInv = INV_TWO;

        bytes memory alpha = Fp.mul(Fp.add(a.c0, t), twoInv);

        bytes memory x0 = Fp.sqrt(alpha);
        if (!Fp.eq(Fp.sqr(x0), alpha)) {
            // Try x0 = sqrt((c0 - t) / 2)
            bytes memory beta = Fp.mul(Fp.sub(a.c0, t), twoInv);
            x0 = Fp.sqrt(beta);
        }

        // x1 = c1 / (2 * x0)
        bytes memory x1 = Fp.mul(a.c1, Fp.inv(Fp.add(x0, x0)));

        root = Element(x0, x1);

        // Verify by squaring back
        Element memory check = sqr(root);
        if (!eq(check, a)) {
            return (false, zero());
        }

        return (true, root);
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /// @notice Conjugate: (c0, -c1).
    function conjugate(Element memory a) internal pure returns (Element memory) {
        return Element(a.c0, Fp.neg(a.c1));
    }

    /// @notice Multiply by i: i*(c0 + c1*i) = -c1 + c0*i.
    function mulByI(Element memory a) internal pure returns (Element memory) {
        return Element(Fp.neg(a.c1), a.c0);
    }
}
