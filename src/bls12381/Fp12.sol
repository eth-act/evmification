// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp2} from "./Fp2.sol";
import {Fp6} from "./Fp6.sol";

/// @title Fp12
/// @notice Dodecic extension field Fp12 = Fp6[w]/(w^2 - v) arithmetic.
/// @dev An Fp12 element is (c0, c1) representing c0 + c1*w where w^2 = v.
///      Used as the target group GT for BLS12-381 pairings.
library Fp12 {
    struct Element {
        Fp6.Element c0;
        Fp6.Element c1;
    }

    /// @dev BLS12-381 parameter |x| = 0xd201000000010000 (64 bits).
    ///      x is negative, so after exponentiation we conjugate.
    uint256 constant BLS_X = 0xd201000000010000;

    // ── Constructors ────────────────────────────────────────────────────

    /// @notice Returns the zero element.
    function zero() internal pure returns (Element memory) {
        return Element(Fp6.zero(), Fp6.zero());
    }

    /// @notice Returns the one element.
    function one() internal pure returns (Element memory) {
        return Element(Fp6.one(), Fp6.zero());
    }

    // ── Arithmetic ──────────────────────────────────────────────────────

    /// @notice (a + b) in Fp12.
    function add(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp6.add(a.c0, b.c0), Fp6.add(a.c1, b.c1));
    }

    /// @notice (a - b) in Fp12.
    function sub(Element memory a, Element memory b) internal pure returns (Element memory) {
        return Element(Fp6.sub(a.c0, b.c0), Fp6.sub(a.c1, b.c1));
    }

    /// @notice -a in Fp12.
    function neg(Element memory a) internal pure returns (Element memory) {
        return Element(Fp6.neg(a.c0), Fp6.neg(a.c1));
    }

    /// @notice (a * b) in Fp12.
    function mul(Element memory a, Element memory b) internal pure returns (Element memory) {
        Fp6.Element memory aa = Fp6.mul(a.c0, b.c0);
        Fp6.Element memory bb = Fp6.mul(a.c1, b.c1);

        // c1 = (a.c0 + a.c1) * (b.c0 + b.c1) - aa - bb
        Fp6.Element memory rc1 =
            Fp6.sub(Fp6.sub(Fp6.mul(Fp6.add(a.c0, a.c1), Fp6.add(b.c0, b.c1)), aa), bb);

        // c0 = aa + bb * v (mulByNonResidue)
        Fp6.Element memory rc0 = Fp6.add(aa, Fp6.mulByNonResidue(bb));

        return Element(rc0, rc1);
    }

    /// @notice a^2 in Fp12.
    function sqr(Element memory a) internal pure returns (Element memory) {
        Fp6.Element memory ab = Fp6.mul(a.c0, a.c1);

        // c1 = 2 * ab
        Fp6.Element memory rc1 = Fp6.add(ab, ab);

        // c0 = (c0 + c1) * (c0 + mulByNonResidue(c1)) - ab - mulByNonResidue(ab)
        Fp6.Element memory rc0 = Fp6.sub(
            Fp6.sub(Fp6.mul(Fp6.add(a.c0, a.c1), Fp6.add(a.c0, Fp6.mulByNonResidue(a.c1))), ab),
            Fp6.mulByNonResidue(ab)
        );

        return Element(rc0, rc1);
    }

    /// @notice a^{-1} in Fp12.
    function inv(Element memory a) internal pure returns (Element memory) {
        // t = c0^2 - mulByNonResidue(c1^2)
        Fp6.Element memory t = Fp6.sub(Fp6.sqr(a.c0), Fp6.mulByNonResidue(Fp6.sqr(a.c1)));
        Fp6.Element memory tInv = Fp6.inv(t);

        return Element(Fp6.mul(a.c0, tInv), Fp6.neg(Fp6.mul(a.c1, tInv)));
    }

    /// @notice Conjugate: (c0, -c1). This is the Frobenius to the 6th power.
    function conjugate(Element memory a) internal pure returns (Element memory) {
        return Element(a.c0, Fp6.neg(a.c1));
    }

    /// @notice Multiply by sparse element from line evaluation: (c0, c1, 0, 0, c4, 0).
    /// @dev The line function produces an Fp12 element with structure:
    ///      Fp6 part0 = (c0, c1, 0) and Fp6 part1 = (0, c4, 0)
    ///      where c0, c1, c4 are in Fp2.
    function mul_by_014(
        Element memory self,
        Fp2.Element memory c0,
        Fp2.Element memory c1,
        Fp2.Element memory c4
    ) internal pure returns (Element memory) {
        Fp6.Element memory aa = Fp6.mul_by_01(self.c0, c0, c1);
        Fp6.Element memory bb = Fp6.mul_by_1(self.c1, c4);

        // o = c1 + c4
        Fp2.Element memory o = Fp2.add(c1, c4);

        // rc1 = (self.c0 + self.c1).mul_by_01(c0, o) - aa - bb
        Fp6.Element memory rc1 =
            Fp6.sub(Fp6.sub(Fp6.mul_by_01(Fp6.add(self.c0, self.c1), c0, o), aa), bb);

        // rc0 = mulByNonResidue(bb) + aa
        Fp6.Element memory rc0 = Fp6.add(Fp6.mulByNonResidue(bb), aa);

        return Element(rc0, rc1);
    }

    /// @notice Frobenius endomorphism on Fp12.
    function frobenius_map(Element memory self, uint256 power)
        internal
        pure
        returns (Element memory)
    {
        Fp6.Element memory fc0 = Fp6.frobenius_map(self.c0, power);
        Fp6.Element memory fc1 = Fp6.frobenius_map(self.c1, power);

        // Multiply fc1 by FROBENIUS_COEFF_FP12_C1[power % 12]
        // This coefficient is always of the form (x, 0) in Fp2 — i.e., it's real.
        // We can multiply the whole Fp6 by the Fp2 scalar.
        Fp2.Element memory coeff = _frobeniusCoeffFp12C1(power % 12);
        fc1 = Fp6.Element(Fp2.mul(fc1.c0, coeff), Fp2.mul(fc1.c1, coeff), Fp2.mul(fc1.c2, coeff));

        return Element(fc0, fc1);
    }

    /// @notice Cyclotomic squaring for elements in GΦ6(p^2).
    /// @dev For now, uses standard Fp12 squaring. Can be optimized later.
    function cyclotomic_square(Element memory a) internal pure returns (Element memory) {
        return sqr(a);
    }

    /// @notice Exponentiate by |x| (the BLS parameter) using square-and-multiply.
    /// @dev Since x is negative for BLS12-381, caller must conjugate the result.
    function cyclotomic_exp(Element memory a) internal pure returns (Element memory) {
        Element memory result = one();

        // Iterate from bit 62 down to 0 (bit 63 is the MSB, which is 1, so start with result = a)
        // BLS_X = 0xd201000000010000
        // Binary: 1101001000000001000000000000000000000000000000010000000000000000
        // MSB is bit 63.
        result = a; // accounts for MSB = 1

        for (uint256 i = 62;; i--) {
            result = cyclotomic_square(result);
            if ((BLS_X >> i) & 1 == 1) {
                result = mul(result, a);
            }
            if (i == 0) break;
        }

        return result;
    }

    // ── Predicates ──────────────────────────────────────────────────────

    /// @notice Returns true if a == 0.
    function isZero(Element memory a) internal pure returns (bool) {
        return Fp6.isZero(a.c0) && Fp6.isZero(a.c1);
    }

    /// @notice Returns true if a == b.
    function eq(Element memory a, Element memory b) internal pure returns (bool) {
        return Fp6.eq(a.c0, b.c0) && Fp6.eq(a.c1, b.c1);
    }

    // ── Frobenius constants for Fp12 ────────────────────────────────────
    // FROBENIUS_COEFF_FP12_C1[i] = (1+u)^((p^i - 1) / 6)
    // These are all in Fp (i.e., Fp2 elements with c1 = 0).

    function _frobeniusCoeffFp12C1(uint256 rem) private pure returns (Fp2.Element memory) {
        if (rem == 0) {
            return Fp2.one();
        } else if (rem == 1) {
            return Fp2.Element(
                hex"06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09",
                hex"135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2"
            );
        } else if (rem == 2) {
            return Fp2.Element(
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
                new bytes(48)
            );
        } else if (rem == 3) {
            return Fp2.Element(
                hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
                hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"
            );
        } else if (rem == 4) {
            return Fp2.Element(
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
                new bytes(48)
            );
        } else if (rem == 5) {
            return Fp2.Element(
                hex"012d1137b8a6a8374e464dea5bcfd41eb3f8afc0ee248cadbe203411c66fb3a5946ae52d684fa7ed977e6cfc22566ea0",
                hex"0d8c49e76e40415ff6c2e10db1e26622f0f995ab55636dcb063d5e228788998cfa7ab5e1eb3e839e7d18e1a5ef9f18b2"
            );
        } else if (rem == 6) {
            // This is p - 1 in Fp, 0 in imaginary part
            return Fp2.Element(
                hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
                new bytes(48)
            );
        } else if (rem == 7) {
            return Fp2.Element(
                hex"13b20f4fca8adb3a4b2d184e6916c539e0fad3e8e43bb4a5e1b0581b1d01570fea04cc1c46f02c4059ee14afab5ef74b",
                hex"04c58e143280e02030f0bfe3ce8a7cee7eb280e60ce7fb4176efcf17ea2eedb09cf1a4789a3b68b62a65d5fecb1a4e10"
            );
        } else if (rem == 8) {
            return Fp2.Element(
                hex"00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe",
                new bytes(48)
            );
        } else if (rem == 9) {
            return Fp2.Element(
                hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa",
                hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"
            );
        } else if (rem == 10) {
            return Fp2.Element(
                hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac",
                new bytes(48)
            );
        } else {
            // rem == 11
            return Fp2.Element(
                hex"17faf2d98d3375fabb351d327980e7de3255ffd13892b66ba1c7f2fb1c6a5cbb17bb8bab89d15aa5c7c6c2dadadb2b29",
                hex"15dae19658143e6b1578dd3c5c5a35a16ab966d23ab3dee798e7e0b28cae404db2b3f0498ad52c073cbf04fffe7ebc8c"
            );
        }
    }
}
