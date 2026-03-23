// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "./Fp.sol";
import {Fp2} from "./Fp2.sol";

/// @title Fp6
/// @notice Sextic extension field Fp6 = Fp2[v]/(v^3 - (1+u)) arithmetic.
/// @dev An Fp6 element is (c0, c1, c2) representing c0 + c1*v + c2*v^2.
///      The non-residue (twist) is beta = (1, 1) in Fp2, so v^3 = (1+u).
library Fp6 {
    struct Element {
        Fp2.Element c0;
        Fp2.Element c1;
        Fp2.Element c2;
    }

    // ── Constructors ────────────────────────────────────────────────────

    /// @notice Returns the zero element (0, 0, 0).
    function zero() internal pure returns (Element memory) {
        return Element(Fp2.zero(), Fp2.zero(), Fp2.zero());
    }

    /// @notice Returns the one element (1, 0, 0).
    function one() internal pure returns (Element memory) {
        return Element(Fp2.one(), Fp2.zero(), Fp2.zero());
    }

    // ── Arithmetic ──────────────────────────────────────────────────────

    /// @notice (a + b) in Fp6.
    function add(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp2.add(a.c0, b.c0), Fp2.add(a.c1, b.c1), Fp2.add(a.c2, b.c2));
    }

    /// @notice (a - b) in Fp6.
    function sub(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp2.sub(a.c0, b.c0), Fp2.sub(a.c1, b.c1), Fp2.sub(a.c2, b.c2));
    }

    /// @notice -a in Fp6.
    function neg(Element memory a) internal pure returns (Element memory) {
        return Element(Fp2.neg(a.c0), Fp2.neg(a.c1), Fp2.neg(a.c2));
    }

    /// @notice Multiply Fp2 element by the non-residue (1+u).
    /// @dev (a0 + a1*u) * (1 + u) = (a0 - a1) + (a0 + a1)*u
    function mulByNonResidueFp2(Fp2.Element memory a) internal pure returns (Fp2.Element memory) {
        return Fp2.Element(Fp.sub(a.c0, a.c1), Fp.add(a.c0, a.c1));
    }

    /// @notice Multiply Fp6 element by v (the non-residue in Fp6).
    /// @dev (c0, c1, c2) * v = (c2 * beta_fp2, c0, c1)
    function mulByNonResidue(Element memory a) internal pure returns (Element memory) {
        return Element(mulByNonResidueFp2(a.c2), a.c0, a.c1);
    }

    /// @notice (a * b) in Fp6 using Karatsuba (5 Fp2.mul).
    function mul(Element memory a, Element memory b) internal pure returns (Element memory) {
        Fp2.Element memory v0 = Fp2.mul(a.c0, b.c0);
        Fp2.Element memory v1 = Fp2.mul(a.c1, b.c1);
        Fp2.Element memory v2 = Fp2.mul(a.c2, b.c2);

        // c0 = v0 + ((a1+a2)*(b1+b2) - v1 - v2) * beta
        Fp2.Element memory c0 = Fp2.add(
            v0,
            mulByNonResidueFp2(
                Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(a.c1, a.c2), Fp2.add(b.c1, b.c2)), v1), v2)
            )
        );

        // c1 = (a0+a1)*(b0+b1) - v0 - v1 + v2*beta
        Fp2.Element memory c1 = Fp2.add(
            Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(a.c0, a.c1), Fp2.add(b.c0, b.c1)), v0), v1),
            mulByNonResidueFp2(v2)
        );

        // c2 = (a0+a2)*(b0+b2) - v0 - v2 + v1
        Fp2.Element memory c2 = Fp2.add(
            Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(a.c0, a.c2), Fp2.add(b.c0, b.c2)), v0), v2), v1
        );

        return Element(c0, c1, c2);
    }

    /// @notice a^2 in Fp6 using Chung-Hasan SQ3.
    function sqr(Element memory a) internal pure returns (Element memory) {
        Fp2.Element memory s0 = Fp2.sqr(a.c0);
        Fp2.Element memory ab = Fp2.mul(a.c0, a.c1);
        Fp2.Element memory s1 = Fp2.add(ab, ab); // 2*c0*c1
        Fp2.Element memory s2 = Fp2.sqr(Fp2.add(Fp2.sub(a.c0, a.c1), a.c2));
        Fp2.Element memory bc = Fp2.mul(a.c1, a.c2);
        Fp2.Element memory s3 = Fp2.add(bc, bc); // 2*c1*c2
        Fp2.Element memory s4 = Fp2.sqr(a.c2);

        // result.c0 = s0 + s3*beta
        Fp2.Element memory c0 = Fp2.add(s0, mulByNonResidueFp2(s3));
        // result.c1 = s1 + s4*beta
        Fp2.Element memory c1 = Fp2.add(s1, mulByNonResidueFp2(s4));
        // result.c2 = s1 + s2 + s3 - s0 - s4
        Fp2.Element memory c2 = Fp2.sub(Fp2.sub(Fp2.add(Fp2.add(s1, s2), s3), s0), s4);

        return Element(c0, c1, c2);
    }

    /// @notice a^{-1} in Fp6.
    function inv(Element memory a) internal pure returns (Element memory) {
        Fp2.Element memory c0s = Fp2.sqr(a.c0);
        Fp2.Element memory c1s = Fp2.sqr(a.c1);
        Fp2.Element memory c2s = Fp2.sqr(a.c2);

        Fp2.Element memory c01 = Fp2.mul(a.c0, a.c1);
        Fp2.Element memory c02 = Fp2.mul(a.c0, a.c2);
        Fp2.Element memory c12 = Fp2.mul(a.c1, a.c2);

        // A = c0^2 - c1*c2*beta
        Fp2.Element memory A = Fp2.sub(c0s, mulByNonResidueFp2(c12));
        // B = c2^2*beta - c0*c1
        Fp2.Element memory B = Fp2.sub(mulByNonResidueFp2(c2s), c01);
        // C = c1^2 - c0*c2
        Fp2.Element memory C = Fp2.sub(c1s, c02);

        // norm = c0*A + (c2*B + c1*C)*beta
        Fp2.Element memory norm = Fp2.add(
            Fp2.mul(a.c0, A),
            mulByNonResidueFp2(Fp2.add(Fp2.mul(a.c2, B), Fp2.mul(a.c1, C)))
        );

        Fp2.Element memory normInv = Fp2.inv(norm);

        return Element(Fp2.mul(A, normInv), Fp2.mul(B, normInv), Fp2.mul(C, normInv));
    }

    /// @notice Multiply Fp6 by sparse element (c0, c1, 0).
    function mul_by_01(Element memory self, Fp2.Element memory c0, Fp2.Element memory c1)
        internal
        pure
        returns (Element memory)
    {
        Fp2.Element memory a_a = Fp2.mul(self.c0, c0);
        Fp2.Element memory b_b = Fp2.mul(self.c1, c1);

        // t1 = mulByNonResidueFp2(self.c2 * c1) + a_a
        Fp2.Element memory t1 = Fp2.add(mulByNonResidueFp2(Fp2.mul(self.c2, c1)), a_a);

        // t2 = (c0 + c1) * (self.c0 + self.c1) - a_a - b_b
        Fp2.Element memory t2 =
            Fp2.sub(Fp2.sub(Fp2.mul(Fp2.add(c0, c1), Fp2.add(self.c0, self.c1)), a_a), b_b);

        // t3 = self.c2 * c0 + b_b
        Fp2.Element memory t3 = Fp2.add(Fp2.mul(self.c2, c0), b_b);

        return Element(t1, t2, t3);
    }

    /// @notice Multiply Fp6 by sparse element (0, c1, 0).
    function mul_by_1(Element memory self, Fp2.Element memory c1)
        internal
        pure
        returns (Element memory)
    {
        return Element(
            mulByNonResidueFp2(Fp2.mul(self.c2, c1)),
            Fp2.mul(self.c0, c1),
            Fp2.mul(self.c1, c1)
        );
    }

    /// @notice Frobenius endomorphism on Fp6.
    /// @dev For odd powers, conjugate each Fp2 component; then multiply c1, c2 by constants.
    function frobenius_map(Element memory self, uint256 power)
        internal
        pure
        returns (Element memory)
    {
        uint256 rem = power % 6;

        Fp2.Element memory fc0;
        Fp2.Element memory fc1;
        Fp2.Element memory fc2;

        if (power % 2 == 1) {
            fc0 = Fp2.conjugate(self.c0);
            fc1 = Fp2.conjugate(self.c1);
            fc2 = Fp2.conjugate(self.c2);
        } else {
            fc0 = self.c0;
            fc1 = self.c1;
            fc2 = self.c2;
        }

        // Multiply c1 by FROBENIUS_COEFF_C1[rem]
        fc1 = Fp2.mul(fc1, _frobeniusCoeffC1(rem));
        // Multiply c2 by FROBENIUS_COEFF_C2[rem]
        fc2 = Fp2.mul(fc2, _frobeniusCoeffC2(rem));

        return Element(fc0, fc1, fc2);
    }

    // ── Predicates ──────────────────────────────────────────────────────

    /// @notice Returns true if a == (0, 0, 0).
    function isZero(Element memory a) internal pure returns (bool) {
        return Fp2.isZero(a.c0) && Fp2.isZero(a.c1) && Fp2.isZero(a.c2);
    }

    /// @notice Returns true if a == b.
    function eq(Element memory a, Element memory b) internal pure returns (bool) {
        return Fp2.eq(a.c0, b.c0) && Fp2.eq(a.c1, b.c1) && Fp2.eq(a.c2, b.c2);
    }

    // ── Frobenius constants ─────────────────────────────────────────────
    // From zkcrypto/bls12_381 / noble-curves reference implementations.
    // FROBENIUS_COEFF_FP6_C1[i] = (1+u)^((p^i - 1) / 3)
    // FROBENIUS_COEFF_FP6_C2[i] = (1+u)^((2*(p^i - 1)) / 3)

    function _frobeniusCoeffC1(uint256 rem) private pure returns (Fp2.Element memory) {
        if (rem == 0) {
            // (1, 0)
            return Fp2.one();
        } else if (rem == 1) {
            // (0, 0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac)
            return Fp2.Element(
                new bytes(48),
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"
            );
        } else if (rem == 2) {
            // (0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe, 0)
            return Fp2.Element(
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
                new bytes(48)
            );
        } else if (rem == 3) {
            // (0, 1)
            return Fp2.Element(new bytes(48), Fp.fromUint256(1));
        } else if (rem == 4) {
            // (0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac, 0)
            return Fp2.Element(
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
                new bytes(48)
            );
        } else {
            // rem == 5: (0, 0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe)
            return Fp2.Element(
                new bytes(48),
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"
            );
        }
    }

    function _frobeniusCoeffC2(uint256 rem) private pure returns (Fp2.Element memory) {
        if (rem == 0) {
            // (1, 0)
            return Fp2.one();
        } else if (rem == 1) {
            // (0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe, 0)
            return Fp2.Element(
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
                new bytes(48)
            );
        } else if (rem == 2) {
            // (0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad, 0)
            return Fp2.Element(
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad",
                new bytes(48)
            );
        } else if (rem == 3) {
            // (0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa, 0)
            // This is p - 1
            return Fp2.Element(
                hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
                new bytes(48)
            );
        } else if (rem == 4) {
            // (0x5f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe, 0)
            return Fp2.Element(
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
                new bytes(48)
            );
        } else {
            // rem == 5:
            // (0x1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad, 0)
            return Fp2.Element(
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad",
                new bytes(48)
            );
        }
    }
}
