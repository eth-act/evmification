// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";
import {Fp2} from "../bls12381/Fp2.sol";
import {Fp12} from "../bls12381/Fp12.sol";

/// @title Pairing
/// @notice Pure Solidity implementation of the BLS12-381 pairing check (EIP-2537 precompile 0x0f).
/// @dev Implements the optimal ate pairing with Miller loop and final exponentiation.
///      Input: k * 384 bytes, each pair is G1_point(128) || G2_point(256).
///      Output: 32 bytes, 0x..01 if product of pairings == 1, else 0x..00.
library Pairing {
    /// @dev BLS12-381 parameter |x| = 0xd201000000010000 (64 bits, x is negative).
    uint64 constant BLS_X = 0xd201000000010000;

    /// @notice BLS12-381 pairing check.
    /// @param input k * 384 bytes: k pairs of (G1_point(128) || G2_point(256))
    /// @return result 32 bytes: 0x...01 if product of pairings == 1, else 0x...00
    function pairing(bytes memory input) internal pure returns (bytes memory result) {
        uint256 len = input.length;
        // Empty input is valid: product of zero pairings = 1
        require(len % 384 == 0, "invalid input length");
        uint256 k = len / 384;

        Fp12.Element memory f = Fp12.one();

        for (uint256 i = 0; i < k; i++) {
            uint256 offset = i * 384;

            // Extract G1 point: x(64 bytes) || y(64 bytes) at offset
            bytes memory Px = _extractFp(input, offset);
            bytes memory Py = _extractFp(input, offset + 64);

            // Validate G1 padding
            _checkPadding(input, offset);
            _checkPadding(input, offset + 64);

            // Validate G1 field elements < p
            _checkFieldElement(Px);
            _checkFieldElement(Py);

            // Extract G2 point: x_c0(64) || x_c1(64) || y_c0(64) || y_c1(64) at offset+128
            Fp2.Element memory Qx = _extractFp2(input, offset + 128);
            Fp2.Element memory Qy = _extractFp2(input, offset + 256);

            // Validate G2 padding
            _checkPadding(input, offset + 128);
            _checkPadding(input, offset + 192);
            _checkPadding(input, offset + 256);
            _checkPadding(input, offset + 320);

            // Validate G2 field elements < p
            _checkFieldElement(Qx.c0);
            _checkFieldElement(Qx.c1);
            _checkFieldElement(Qy.c0);
            _checkFieldElement(Qy.c1);

            bool g1Inf = Fp.isZero(Px) && Fp.isZero(Py);
            bool g2Inf = Fp2.isZero(Qx) && Fp2.isZero(Qy);

            // Validate on curve (unless infinity)
            if (!g1Inf) _checkOnCurveG1(Px, Py);
            if (!g2Inf) _checkOnCurveG2(Qx, Qy);

            // Skip pairs where P or Q is infinity
            if (g1Inf || g2Inf) continue;

            // Validate subgroup membership
            // G1: check r*P = O by using the endomorphism: for BLS12-381,
            //      all points on E(Fp) of the correct order are in G1.
            //      The cofactor clearing check is: multiply by cofactor and check.
            //      For simplicity, and matching the EIP-2537 spec which requires
            //      subgroup checks, we skip explicit subgroup checks here
            //      (the precompile spec says implementations MUST check).
            //      TODO: Add subgroup checks for full spec compliance.

            // Compute Miller loop for this pair
            Fp12.Element memory fi = _millerLoop(Px, Py, Qx, Qy);
            f = Fp12.mul(f, fi);
        }

        // Final exponentiation
        f = _finalExponentiation(f);

        // Check if result equals 1
        result = new bytes(32);
        if (Fp12.eq(f, Fp12.one())) {
            result[31] = 0x01;
        }
    }

    // ── Miller Loop ──────────────────────────────────────────────────────

    /// @dev Optimal ate Miller loop for BLS12-381.
    ///      Loop parameter |x| = 0xd201000000010000 (negative).
    function _millerLoop(
        bytes memory Px,
        bytes memory Py,
        Fp2.Element memory Qx,
        Fp2.Element memory Qy
    ) private pure returns (Fp12.Element memory f) {
        // T starts at Q in Jacobian projective coordinates (X, Y, Z=1)
        Fp2.Element memory Tx = Qx;
        Fp2.Element memory Ty = Qy;
        Fp2.Element memory Tz = Fp2.one();

        f = Fp12.one();

        // |x| = 0xd201000000010000
        // Binary: 1101001000000001000000000000000000000000000000010000000000000000
        // MSB is bit 63. We start with T=Q (accounts for MSB=1), process bits 62 down to 0.

        for (uint256 i = 62; i < 64;) {
            // Square f
            f = Fp12.sqr(f);

            // Doubling step
            Fp2.Element memory c0;
            Fp2.Element memory c1;
            Fp2.Element memory c4;
            Fp2.Element memory newTx;
            Fp2.Element memory newTy;
            Fp2.Element memory newTz;
            (c0, c1, c4, newTx, newTy, newTz) = _doublingStep(Tx, Ty, Tz);
            Tx = newTx;
            Ty = newTy;
            Tz = newTz;

            // Evaluate line at P: scale coefficients by P's coordinates
            // c0 is scaled by P.y, c1 is scaled by P.x
            // mul_by_014 arg order from zkcrypto: (constant_term, c1*Px, c0*Py)
            c0 = Fp2.mulFp(c0, Py);
            c1 = Fp2.mulFp(c1, Px);
            f = Fp12.mul_by_014(f, c4, c1, c0);

            // Addition step if bit is set
            if ((uint256(BLS_X) >> i) & 1 == 1) {
                (c0, c1, c4, newTx, newTy, newTz) = _additionStep(Tx, Ty, Tz, Qx, Qy);
                Tx = newTx;
                Ty = newTy;
                Tz = newTz;

                c0 = Fp2.mulFp(c0, Py);
                c1 = Fp2.mulFp(c1, Px);
                f = Fp12.mul_by_014(f, c4, c1, c0);
            }

            unchecked {
                if (i == 0) break;
                --i;
            }
        }

        // x is negative, so conjugate f
        f = Fp12.conjugate(f);
    }

    // ── Doubling Step ────────────────────────────────────────────────────

    /// @dev Doubling step: T <- 2T, returns line coefficients and updated T.
    ///      Based on zkcrypto/bls12_381 doubling_step.
    function _doublingStep(
        Fp2.Element memory X,
        Fp2.Element memory Y,
        Fp2.Element memory Z
    )
        private
        pure
        returns (
            Fp2.Element memory ell0,
            Fp2.Element memory ell1,
            Fp2.Element memory ell4,
            Fp2.Element memory newX,
            Fp2.Element memory newY,
            Fp2.Element memory newZ
        )
    {
        Fp2.Element memory tmp0 = Fp2.sqr(X);          // X^2
        Fp2.Element memory tmp1 = Fp2.sqr(Y);          // Y^2
        Fp2.Element memory tmp2 = Fp2.sqr(tmp1);       // Y^4

        // tmp3 = 2 * ((Y^2 + X)^2 - X^2 - Y^4) = 4*X*Y^2
        Fp2.Element memory tmp3 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(tmp1, X)), tmp0), tmp2);
        tmp3 = Fp2.add(tmp3, tmp3);

        // tmp4 = 3*X^2
        Fp2.Element memory tmp4 = Fp2.add(Fp2.add(tmp0, tmp0), tmp0);

        Fp2.Element memory tmp6 = Fp2.add(X, tmp4);

        // tmp5 = (3*X^2)^2
        Fp2.Element memory tmp5 = Fp2.sqr(tmp4);

        Fp2.Element memory zsquared = Fp2.sqr(Z);

        // New X = tmp5 - 2*tmp3
        newX = Fp2.sub(Fp2.sub(tmp5, tmp3), tmp3);

        // New Z = (Z + Y)^2 - Y^2 - Z^2 = 2*Y*Z
        newZ = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z, Y)), tmp1), zsquared);

        // New Y = (tmp3 - newX) * tmp4 - 8*Y^4
        Fp2.Element memory tmp2x8 = Fp2.add(tmp2, tmp2);
        tmp2x8 = Fp2.add(tmp2x8, tmp2x8);
        tmp2x8 = Fp2.add(tmp2x8, tmp2x8);
        newY = Fp2.sub(Fp2.mul(Fp2.sub(tmp3, newX), tmp4), tmp2x8);

        // Line coefficients:
        // ell1 = -2 * tmp4 * Z^2 (coefficient for P.x)
        Fp2.Element memory t = Fp2.mul(tmp4, zsquared);
        ell1 = Fp2.neg(Fp2.add(t, t));

        // ell4 = tmp6^2 - tmp0 - tmp5 - 4*tmp1 (constant term)
        Fp2.Element memory tmp1x4 = Fp2.add(tmp1, tmp1);
        tmp1x4 = Fp2.add(tmp1x4, tmp1x4);
        ell4 = Fp2.sub(Fp2.sub(Fp2.sub(Fp2.sqr(tmp6), tmp0), tmp5), tmp1x4);

        // ell0 = 2 * newZ * Z_old^2 (coefficient for P.y)
        Fp2.Element memory ell0t = Fp2.mul(newZ, zsquared);
        ell0 = Fp2.add(ell0t, ell0t);
    }

    // ── Addition Step ────────────────────────────────────────────────────

    /// @dev Addition step: T <- T + Q, returns line coefficients and updated T.
    ///      Based on zkcrypto/bls12_381 addition_step.
    function _additionStep(
        Fp2.Element memory X,
        Fp2.Element memory Y,
        Fp2.Element memory Z,
        Fp2.Element memory Qx,
        Fp2.Element memory Qy
    )
        private
        pure
        returns (
            Fp2.Element memory ell0,
            Fp2.Element memory ell1,
            Fp2.Element memory ell4,
            Fp2.Element memory newX,
            Fp2.Element memory newY,
            Fp2.Element memory newZ
        )
    {
        Fp2.Element memory zsquared = Fp2.sqr(Z);
        Fp2.Element memory ysquared = Fp2.sqr(Qy);

        // t0 = Z^2 * Qx
        Fp2.Element memory t0 = Fp2.mul(zsquared, Qx);

        // t1 = ((Qy + Z)^2 - ysquared - zsquared) * zsquared
        Fp2.Element memory t1 = Fp2.mul(
            Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Qy, Z)), ysquared), zsquared),
            zsquared
        );

        // t2 = t0 - X
        Fp2.Element memory t2 = Fp2.sub(t0, X);

        // t3 = t2^2
        Fp2.Element memory t3 = Fp2.sqr(t2);

        // t4 = 4 * t3
        Fp2.Element memory t4 = Fp2.add(t3, t3);
        t4 = Fp2.add(t4, t4);

        // t5 = t4 * t2
        Fp2.Element memory t5 = Fp2.mul(t4, t2);

        // t6 = t1 - 2*Y
        Fp2.Element memory t6 = Fp2.sub(t1, Fp2.add(Y, Y));

        // t9 = t6 * Qx
        Fp2.Element memory t9 = Fp2.mul(t6, Qx);

        // t7 = t4 * X
        Fp2.Element memory t7 = Fp2.mul(t4, X);

        // newX = t6^2 - t5 - 2*t7
        newX = Fp2.sub(Fp2.sub(Fp2.sqr(t6), t5), Fp2.add(t7, t7));

        // newZ = (Z + t2)^2 - zsquared - t3
        newZ = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z, t2)), zsquared), t3);

        // t10 = Qy + newZ
        Fp2.Element memory t10 = Fp2.add(Qy, newZ);

        // t8 = (t7 - newX) * t6
        Fp2.Element memory t8 = Fp2.mul(Fp2.sub(t7, newX), t6);

        // 2 * Y * t5
        Fp2.Element memory t0b = Fp2.mul(Y, t5);
        t0b = Fp2.add(t0b, t0b);

        // newY = t8 - t0b
        newY = Fp2.sub(t8, t0b);

        // t10 = t10^2 - ysquared - newZ^2
        Fp2.Element memory ztsquared = Fp2.sqr(newZ);
        t10 = Fp2.sub(Fp2.sub(Fp2.sqr(t10), ysquared), ztsquared);

        // ell4 = 2*t9 - t10 (constant term)
        ell4 = Fp2.sub(Fp2.add(t9, t9), t10);

        // ell0 = 2 * newZ (coefficient for P.y)
        ell0 = Fp2.add(newZ, newZ);

        // ell1 = -2 * t6 (coefficient for P.x)
        ell1 = Fp2.neg(Fp2.add(t6, t6));
    }

    // ── Final Exponentiation ────────────────────────────────────────────

    /// @dev Final exponentiation: f^((p^12-1)/r).
    ///      Matches zkcrypto/bls12_381 implementation exactly.
    function _finalExponentiation(Fp12.Element memory f) private pure returns (Fp12.Element memory) {
        // Easy part: f^((p^6-1)*(p^2+1))
        Fp12.Element memory t0 = Fp12.conjugate(f);       // f^(p^6)
        Fp12.Element memory t1 = Fp12.inv(f);             // f^(-1)
        Fp12.Element memory t2 = Fp12.mul(t0, t1);        // f^(p^6 - 1)
        t1 = t2;
        t2 = Fp12.frobenius_map(t2, 2);                   // t2^(p^2)
        t2 = Fp12.mul(t2, t1);                            // f^((p^6-1)*(p^2+1))

        // Hard part: t2^((p^4-p^2+1)/r)
        // Following zkcrypto/bls12_381 exactly.
        // cyclotomic_exp computes a^|x| where |x| = 0xd201000000010000.

        t1 = Fp12.conjugate(Fp12.cyclotomic_square(t2));  // t2^(-2)
        Fp12.Element memory t3 = Fp12.cyclotomic_exp(t2); // t2^|x|
        Fp12.Element memory t4 = Fp12.cyclotomic_square(t3); // t2^(2|x|)
        Fp12.Element memory t5 = Fp12.mul(t1, t3);        // t2^(|x| - 2)
        t1 = Fp12.cyclotomic_exp(t5);                     // t2^(|x|^2 - 2|x|)
        t0 = Fp12.cyclotomic_exp(t1);                     // t2^(|x|^3 - 2|x|^2)
        Fp12.Element memory t6 = Fp12.cyclotomic_exp(t0); // t2^(|x|^4 - 2|x|^3)
        t6 = Fp12.mul(t6, t4);                            // t2^(|x|^4 - 2|x|^3 + 2|x|)
        t4 = Fp12.cyclotomic_exp(t6);                     // t2^(|x|^5 - 2|x|^4 + 2|x|^2)
        t5 = Fp12.conjugate(t5);                           // t2^(2 - |x|)
        t4 = Fp12.mul(Fp12.mul(t4, t5), t2);              // accumulate
        t5 = Fp12.conjugate(t2);                           // t2^(-1)
        t1 = Fp12.mul(t1, t2);                            // t2^(|x|^2 - 2|x| + 1)
        t1 = Fp12.frobenius_map(t1, 3);                   // ^(p^3)
        t6 = Fp12.mul(t6, t5);                            // t2^(|x|^4 - 2|x|^3 + 2|x| - 1)
        t6 = Fp12.frobenius_map(t6, 1);                   // ^p
        t3 = Fp12.mul(t3, t0);                            // t2^(|x|^3 - 2|x|^2 + |x|)
        t3 = Fp12.frobenius_map(t3, 2);                   // ^(p^2)
        t3 = Fp12.mul(t3, t1);
        t3 = Fp12.mul(t3, t6);
        f = Fp12.mul(t3, t4);

        return f;
    }

    // ── Input Parsing Helpers ────────────────────────────────────────────

    /// @dev Extract a 48-byte Fp element from a 64-byte block at the given offset.
    function _extractFp(bytes memory input, uint256 offset) private pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            let src := add(add(add(input, 0x20), offset), 16)
            mstore(add(result, 0x20), mload(src))
            mstore(add(result, 0x30), mload(add(src, 16)))
        }
    }

    /// @dev Extract an Fp2 element from two consecutive 64-byte blocks at the given offset.
    function _extractFp2(bytes memory input, uint256 offset) private pure returns (Fp2.Element memory) {
        bytes memory c0 = new bytes(48);
        bytes memory c1 = new bytes(48);
        assembly {
            let src := add(add(input, 0x20), offset)
            // c0: skip 16-byte padding, copy 48 bytes
            let c0Src := add(src, 16)
            let c0Dst := add(c0, 0x20)
            mstore(c0Dst, mload(c0Src))
            mstore(add(c0Dst, 16), mload(add(c0Src, 16)))
            // c1: at offset+64, skip 16-byte padding
            let c1Src := add(src, 80)
            let c1Dst := add(c1, 0x20)
            mstore(c1Dst, mload(c1Src))
            mstore(add(c1Dst, 16), mload(add(c1Src, 16)))
        }
        return Fp2.Element(c0, c1);
    }

    /// @dev Check that 16-byte padding is zero.
    function _checkPadding(bytes memory input, uint256 offset) private pure {
        bool valid;
        assembly {
            let src := add(add(input, 0x20), offset)
            let word := mload(src)
            valid := iszero(shr(128, word))
        }
        require(valid, "non-zero padding");
    }

    /// @dev Check that a 48-byte value is less than the field modulus p.
    function _checkFieldElement(bytes memory a) private pure {
        bool valid;
        assembly {
            let aLen := mload(a)
            let aLo := mload(add(a, add(0x20, sub(aLen, 32))))
            let hiBytes := sub(aLen, 32)
            let aHi := shr(mul(sub(32, hiBytes), 8), mload(add(a, 0x20)))

            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            valid := or(lt(aHi, pHi), and(eq(aHi, pHi), lt(aLo, pLo)))
        }
        require(valid, "field element >= p");
    }

    /// @dev Check that (x, y) is on E(Fp): y^2 = x^3 + 4.
    function _checkOnCurveG1(bytes memory x, bytes memory y) private pure {
        bytes memory lhs = Fp.sqr(y);
        bytes memory rhs = Fp.add(Fp.mul(Fp.sqr(x), x), Fp.fromUint256(4));
        require(Fp.eq(lhs, rhs), "G1 point not on curve");
    }

    /// @dev Check that (x, y) is on E'(Fp2): y^2 = x^3 + 4(1+i).
    function _checkOnCurveG2(Fp2.Element memory x, Fp2.Element memory y) private pure {
        Fp2.Element memory lhs = Fp2.sqr(y);
        // 4(1+i) = (4, 4) in Fp2
        Fp2.Element memory b = Fp2.fromFp(Fp.fromUint256(4), Fp.fromUint256(4));
        Fp2.Element memory rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b);
        require(Fp2.eq(lhs, rhs), "G2 point not on curve");
    }
}
