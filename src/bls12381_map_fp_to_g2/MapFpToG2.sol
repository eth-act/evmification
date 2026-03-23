// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";
import {Fp2} from "../bls12381/Fp2.sol";

/// @title MapFpToG2
/// @notice Pure Solidity implementation of MAP_FP_TO_G2 (EIP-2537, address 0x11).
/// @dev Implements simplified SWU map to isogenous curve E'2 followed by 3-isogeny to E2
///      and cofactor clearing.
library MapFpToG2 {
    // ── Main entry point ────────────────────────────────────────────

    /// @notice Map a field element to a G2 point (EIP-2537 format).
    /// @param input 128 bytes: two 64-byte Fp elements (c0, c1 of Fp2 element).
    /// @return output 256 bytes: four 64-byte padded Fp elements (x.c0, x.c1, y.c0, y.c1).
    function mapToG2(bytes memory input) internal pure returns (bytes memory output) {
        require(input.length == 128, "invalid input length");

        // Extract two 48-byte field elements (each preceded by 16-byte zero padding)
        bytes memory c0 = new bytes(48);
        bytes memory c1 = new bytes(48);
        assembly {
            // c0: skip 32 (length) + 16 (padding) = offset 0x30
            let src := add(input, 0x30)
            let dst := add(c0, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
            // c1: skip 32 (length) + 64 (first element) + 16 (padding) = offset 0x70
            src := add(input, 0x70)
            dst := add(c1, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }

        Fp2.Element memory u = Fp2.fromFp(c0, c1);

        // SWU returns projective x = xN/xD and y
        (Fp2.Element memory xN, Fp2.Element memory xD, Fp2.Element memory yp) = _sswuProjective(u);

        // Isogeny in projective form, outputs Jacobian point
        (Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ) = _iso3Projective(xN, xD, yp);

        // Clear cofactor in Jacobian coordinates
        (Fp2.Element memory x, Fp2.Element memory y) = _clearCofactorJac(jX, jY, jZ);

        // Encode as 256-byte output: 4 x (16-zero-pad || 48-byte Fp)
        output = new bytes(256);
        assembly {
            let dst := add(output, 0x20)
            // x.c0
            let src := mload(x) // x.c0 pointer
            src := add(src, 0x20)
            mstore(add(dst, 0x10), mload(src))
            mstore(add(dst, 0x30), mload(add(src, 0x20)))
            // x.c1
            src := mload(add(x, 0x20)) // x.c1 pointer
            src := add(src, 0x20)
            mstore(add(dst, 0x50), mload(src))
            mstore(add(dst, 0x70), mload(add(src, 0x20)))
            // y.c0
            src := mload(y) // y.c0 pointer
            src := add(src, 0x20)
            mstore(add(dst, 0x90), mload(src))
            mstore(add(dst, 0xB0), mload(add(src, 0x20)))
            // y.c1
            src := mload(add(y, 0x20)) // y.c1 pointer
            src := add(src, 0x20)
            mstore(add(dst, 0xD0), mload(src))
            mstore(add(dst, 0xF0), mload(add(src, 0x20)))
        }
    }

    // ── Simplified SWU (RFC 9380) over Fp2 — projective output ────

    /// @dev Returns (xN, xD, y) where x' = xN/xD, avoiding the inversion.
    function _sswuProjective(Fp2.Element memory u)
        private
        pure
        returns (Fp2.Element memory xN, Fp2.Element memory xD, Fp2.Element memory y)
    {
        Fp2.Element memory A = _aPrime();
        Fp2.Element memory B = _bPrime();
        Fp2.Element memory Z = _z();
        Fp2.Element memory ONE_FP2 = Fp2.one();

        // Step 1: tv1 = u^2
        Fp2.Element memory tv1 = Fp2.sqr(u);
        // Step 2: tv1 = Z * tv1
        tv1 = Fp2.mul(Z, tv1);
        // Step 3: tv2 = tv1^2
        Fp2.Element memory tv2 = Fp2.sqr(tv1);
        // Step 4: tv2 = tv2 + tv1
        tv2 = Fp2.add(tv2, tv1);
        // Step 5: tv3 = tv2 + 1
        Fp2.Element memory tv3 = Fp2.add(tv2, ONE_FP2);
        // Step 6: tv3 = B' * tv3
        tv3 = Fp2.mul(B, tv3);
        // Step 7: tv4 = CMOV(Z, -tv2, tv2 != 0)
        Fp2.Element memory tv4 = Fp2.isZero(tv2) ? Z : Fp2.neg(tv2);
        // Step 8: tv4 = A' * tv4
        tv4 = Fp2.mul(A, tv4);
        // Step 9: tv2 = tv3^2
        tv2 = Fp2.sqr(tv3);
        // Step 10: tv6 = tv4^2
        Fp2.Element memory tv6 = Fp2.sqr(tv4);
        // Step 11: tv5 = A' * tv6
        Fp2.Element memory tv5 = Fp2.mul(A, tv6);
        // Step 12: tv2 = tv2 + tv5
        tv2 = Fp2.add(tv2, tv5);
        // Step 13: tv2 = tv2 * tv3
        tv2 = Fp2.mul(tv2, tv3);
        // Step 14: tv6 = tv6 * tv4
        tv6 = Fp2.mul(tv6, tv4);
        // Step 15: tv5 = B' * tv6
        tv5 = Fp2.mul(B, tv6);
        // Step 16: tv2 = tv2 + tv5
        tv2 = Fp2.add(tv2, tv5);
        // Step 17: xN_candidate = tv1 * tv3
        xN = Fp2.mul(tv1, tv3);
        // Step 18: sqrt_ratio(tv2, tv6)
        (bool is_gx1_square, Fp2.Element memory y1) = _sqrtRatioFp2(tv2, tv6);
        // Step 19: y = tv1 * u
        y = Fp2.mul(tv1, u);
        // Step 20: y = y * y1
        y = Fp2.mul(y, y1);
        // Step 21: xN = CMOV(xN, tv3, is_gx1_square)
        xN = is_gx1_square ? tv3 : xN;
        // Step 22: y = CMOV(y, y1, is_gx1_square)
        y = is_gx1_square ? y1 : y;
        // Step 23-24: if sgn0(u) != sgn0(y), negate y
        if (Fp2.sgn0(u) != Fp2.sgn0(y)) {
            y = Fp2.neg(y);
        }
        // Return projective: x' = xN / tv4 (don't invert)
        xD = tv4;
    }

    // ── sqrt_ratio for Fp2 ────────────────────────────────────────

    function _sqrtRatioFp2(Fp2.Element memory u, Fp2.Element memory v)
        private
        pure
        returns (bool, Fp2.Element memory)
    {
        Fp2.Element memory vInv = Fp2.inv(v);
        Fp2.Element memory uOverV = Fp2.mul(u, vInv);
        (bool exists, Fp2.Element memory s) = Fp2.sqrt(uOverV);
        if (exists) {
            return (true, s);
        }
        // Not a QR — multiply by Z and try again
        Fp2.Element memory Z = _z();
        Fp2.Element memory zUOverV = Fp2.mul(Z, uOverV);
        (exists, s) = Fp2.sqrt(zUOverV);
        return (false, s);
    }

    // ── 3-Isogeny from E'2 to E2 (projective) ───────────────────

    /// @dev Evaluates 3-isogeny in homogeneous form and outputs Jacobian point.
    ///      Input: x' = N/D (projective), y' (affine on E'2).
    ///      Output: (X_j, Y_j, Z_j) Jacobian on E2.
    function _iso3Projective(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element memory yp)
        private
        pure
        returns (Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ)
    {
        // Evaluate all 4 polynomials in homogeneous form
        (Fp2.Element memory xNumH, ) = _evalPolyHom(N, D, _xNumCoeffs());
        (Fp2.Element memory xDenH, ) = _evalPolyMonicHom(N, D, _xDenCoeffs());
        (Fp2.Element memory yNumH, ) = _evalPolyHom(N, D, _yNumCoeffs());
        (Fp2.Element memory yDenH, ) = _evalPolyMonicHom(N, D, _yDenCoeffs());

        // The isogeny output in projective coordinates:
        // x_E = xNumH / (xDenH * D)
        // y_E = yp * yNumH / yDenH
        //
        // As projective (X:Y:Z) with x=X/Z, y=Y/Z:
        // X = xNumH * yDenH
        // Y = yp * yNumH * xDenH * D
        // Z = xDenH * D * yDenH
        //
        // Convert to Jacobian (X_j:Y_j:Z_j) with x=X_j/Z_j^2, y=Y_j/Z_j^3:
        // Z_j = Z = xDenH * D * yDenH
        // X_j = X * Z = xNumH * yDenH * Z_j
        // Y_j = Y * Z^2 = yp * yNumH * xDenH * D * Z_j^2

        jZ = Fp2.mul(Fp2.mul(xDenH, D), yDenH);
        jX = Fp2.mul(Fp2.mul(xNumH, yDenH), jZ);
        Fp2.Element memory jZ2 = Fp2.sqr(jZ);
        jY = Fp2.mul(Fp2.mul(Fp2.mul(yp, yNumH), Fp2.mul(xDenH, D)), jZ2);
    }

    // ── Cofactor clearing on E2 ───────────────────────────────────

    /// @dev ψ (psi) endomorphism constants for BLS12-381 G2.
    ///      psi(x, y) = (conj(x) * PSI_COEFF_X, conj(y) * PSI_COEFF_Y)
    ///      where conj is Fp2 conjugation (a+bi → a-bi).

    /// @dev PSI_COEFF_X = 1/(1+i)^((p-1)/3)  (an Fp2 element with c0=0)
    function _psiCoeffX() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(
            new bytes(48),
            hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"
        );
    }

    /// @dev PSI_COEFF_Y = 1/(1+i)^((p-1)/2)  (an Fp2 element)
    function _psiCoeffY() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(
            hex"135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2",
            hex"06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09"
        );
    }

    /// @dev PSI2_COEFF_X: cube root of unity in Fp, for ψ² x-coordinate.
    ///      ψ²(x, y) = (x * PSI2_COEFF_X, -y)
    bytes constant PSI2_COEFF_X =
        hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac";

    /// @dev Clear the G2 cofactor using the Budroni-Pintore method:
    ///      h(P) = [x² - x - 1]P + [x - 1]ψ(P) + ψ²(2P)
    ///      where x = -0xd201000000010000 (BLS12-381 seed).
    ///
    ///      This uses 2 multiplications by |x| (64-bit) + cheap ψ/ψ² maps,
    ///      instead of a single multiplication by h_eff (636-bit).
    ///      Following blst's implementation in map_to_g2.c.
    ///
    ///      Uses Jacobian coordinates internally to avoid per-operation Fp2.inv.
    ///      Only one Fp2.inv at the very end to convert back to affine.
    ///      Accepts Jacobian input from the projective isogeny.
    function _clearCofactorJac(Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ)
        private
        pure
        returns (Fp2.Element memory, Fp2.Element memory)
    {
        // Convert Jacobian input to affine (1 Fp2.inv)
        (Fp2.Element memory px, Fp2.Element memory py) = _jacToAffine(jX, jY, jZ);

        Fp2.Element memory ONE = Fp2.one();

        // Compute ψ(P) in affine (cheap: 2 mul + conjugations)
        (Fp2.Element memory psiPx, Fp2.Element memory psiPy) = _psiAffine(px, py);

        // Compute ψ²(2P): double P in Jacobian, then apply ψ² in Jacobian
        (Fp2.Element memory twoJX, Fp2.Element memory twoJY, Fp2.Element memory twoJZ) = _g2JacDouble(px, py, ONE);
        (Fp2.Element memory psi2_2X, Fp2.Element memory psi2_2Y, Fp2.Element memory psi2_2Z) = _psi2Jac(twoJX, twoJY, twoJZ);

        // Compute [|x|]P in Jacobian (multiply by seed absolute value)
        (Fp2.Element memory xPX, Fp2.Element memory xPY, Fp2.Element memory xPZ) = _mulBySeedJac(px, py);
        // xP = [-x]P = |x|P  (seed is negative, so _mulBySeed gives |x|*P)

        // blst's approach (z = |x| = -seed):
        // out = ψ²(2P) - P - ψ(P)
        // t0  = [z]P + P = [z+1]P
        // t0  = t0 - ψ(P) = [z+1]P - ψ(P)
        // t1  = [z]*t0 = [z(z+1)]P - [z]ψ(P) = [z²+z]P - [z]ψ(P)
        // out = out + t1 = [z²+z-1]P + [-z-1]ψ(P) + ψ²(2P)
        //
        // Since z = -x: [z²+z-1] = [x²-x-1], [-z-1] = [x-1]. ✓

        // out = ψ²(2P) - P  (mixed add: P is affine)
        (Fp2.Element memory outX, Fp2.Element memory outY, Fp2.Element memory outZ) =
            _g2JacAddMixed(psi2_2X, psi2_2Y, psi2_2Z, px, Fp2.neg(py));
        // out = out - ψ(P)  (mixed add: ψ(P) is affine)
        (outX, outY, outZ) = _g2JacAddMixed(outX, outY, outZ, psiPx, Fp2.neg(psiPy));

        // t0 = [z]P + P = xP + P  (mixed add: P is affine)
        (Fp2.Element memory t0X, Fp2.Element memory t0Y, Fp2.Element memory t0Z) =
            _g2JacAddMixed(xPX, xPY, xPZ, px, py);

        // t0 = t0 - ψ(P)  (mixed add: ψ(P) is affine)
        (t0X, t0Y, t0Z) = _g2JacAddMixed(t0X, t0Y, t0Z, psiPx, Fp2.neg(psiPy));

        // t1 = [z]*t0  (t0 is Jacobian)
        (Fp2.Element memory t1X, Fp2.Element memory t1Y, Fp2.Element memory t1Z) =
            _mulBySeedJacFull(t0X, t0Y, t0Z);

        // out = out + t1  (general Jacobian add)
        (outX, outY, outZ) = _g2JacAdd(outX, outY, outZ, t1X, t1Y, t1Z);

        // Convert back to affine with a single Fp2.inv
        return _jacToAffine(outX, outY, outZ);
    }

    /// @dev Convert Jacobian (X:Y:Z) to affine (X/Z², Y/Z³) with a single Fp2.inv.
    function _jacToAffine(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory x, Fp2.Element memory y)
    {
        Fp2.Element memory zInv = Fp2.inv(Z);
        Fp2.Element memory zInv2 = Fp2.sqr(zInv);
        Fp2.Element memory zInv3 = Fp2.mul(zInv2, zInv);
        x = Fp2.mul(X, zInv2);
        y = Fp2.mul(Y, zInv3);
    }

    /// @dev ψ endomorphism in affine: psi(x, y) = (conj(x) * PSI_COEFF_X, conj(y) * PSI_COEFF_Y)
    function _psiAffine(Fp2.Element memory px, Fp2.Element memory py)
        private
        pure
        returns (Fp2.Element memory rx, Fp2.Element memory ry)
    {
        rx = Fp2.mul(Fp2.conjugate(px), _psiCoeffX());
        ry = Fp2.mul(Fp2.conjugate(py), _psiCoeffY());
    }

    /// @dev ψ² endomorphism in Jacobian coordinates.
    ///      psi2(X, Y, Z) = (X * PSI2_COEFF_X, -Y, Z)
    function _psi2Jac(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory, Fp2.Element memory, Fp2.Element memory)
    {
        return (
            Fp2.mulFp(X, PSI2_COEFF_X),
            Fp2.neg(Y),
            Z
        );
    }

    /// @dev Multiply a G2 affine point by |x| = 0xd201000000010000 using double-and-add
    ///      in Jacobian coordinates. The base point P is affine, so first add is mixed.
    function _mulBySeedJac(Fp2.Element memory px, Fp2.Element memory py)
        private
        pure
        returns (Fp2.Element memory rX, Fp2.Element memory rY, Fp2.Element memory rZ)
    {
        uint64 seed = 0xd201000000010000;

        // Start with P in Jacobian (Z=1)
        rX = px;
        rY = py;
        rZ = Fp2.one();

        // Process from bit 62 down to 0
        for (uint256 i = 62; i < 64; ) {
            (rX, rY, rZ) = _g2JacDouble(rX, rY, rZ);
            if ((seed >> i) & 1 == 1) {
                // Mixed addition: base point P is affine
                (rX, rY, rZ) = _g2JacAddMixed(rX, rY, rZ, px, py);
            }
            unchecked {
                if (i == 0) break;
                --i;
            }
        }
    }

    /// @dev Multiply a G2 Jacobian point by |x| = 0xd201000000010000 using double-and-add.
    ///      Both accumulator and base are in Jacobian, so uses general Jacobian add.
    ///      We convert the base to affine first with one inversion for cheaper mixed adds.
    function _mulBySeedJacFull(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory rX, Fp2.Element memory rY, Fp2.Element memory rZ)
    {
        // Convert base point to affine for mixed additions (1 inversion, but saves ~5 mul per add)
        (Fp2.Element memory ax, Fp2.Element memory ay) = _jacToAffine(X, Y, Z);

        uint64 seed = 0xd201000000010000;

        rX = ax;
        rY = ay;
        rZ = Fp2.one();

        // Process from bit 62 down to 0
        for (uint256 i = 62; i < 64; ) {
            (rX, rY, rZ) = _g2JacDouble(rX, rY, rZ);
            if ((seed >> i) & 1 == 1) {
                (rX, rY, rZ) = _g2JacAddMixed(rX, rY, rZ, ax, ay);
            }
            unchecked {
                if (i == 0) break;
                --i;
            }
        }
    }

    // ── Jacobian point arithmetic on E2: y^2 = x^3 + 4(1+i) ─────

    /// @dev Point doubling in Jacobian coordinates (a=0).
    ///      From https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
    function _g2JacDouble(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        Fp2.Element memory A = Fp2.sqr(X1);          // A = X1²
        Fp2.Element memory B = Fp2.sqr(Y1);          // B = Y1²
        Fp2.Element memory C = Fp2.sqr(B);           // C = B² = Y1⁴

        // D = 2*((X1+B)² - A - C)
        Fp2.Element memory t = Fp2.sqr(Fp2.add(X1, B));
        t = Fp2.sub(Fp2.sub(t, A), C);
        Fp2.Element memory D = Fp2.add(t, t);

        // E = 3*A
        Fp2.Element memory E = Fp2.add(A, Fp2.add(A, A));

        Fp2.Element memory F = Fp2.sqr(E);           // F = E²

        // X3 = F - 2*D
        X3 = Fp2.sub(F, Fp2.add(D, D));

        // Y3 = E*(D - X3) - 8*C
        Fp2.Element memory eightC = Fp2.add(C, C);   // 2C
        eightC = Fp2.add(eightC, eightC);             // 4C
        eightC = Fp2.add(eightC, eightC);             // 8C
        Y3 = Fp2.sub(Fp2.mul(E, Fp2.sub(D, X3)), eightC);

        // Z3 = 2*Y1*Z1
        Fp2.Element memory yz = Fp2.mul(Y1, Z1);
        Z3 = Fp2.add(yz, yz);
    }

    /// @dev Mixed point addition: Jacobian (X1,Y1,Z1) + affine (x2,y2).
    ///      Z2 is implicitly 1.
    ///      From https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
    function _g2JacAddMixed(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1,
        Fp2.Element memory x2,
        Fp2.Element memory y2
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        // If Z1 == 0 (point at infinity), return (x2, y2, 1)
        if (Fp2.isZero(Z1)) {
            return (x2, y2, Fp2.one());
        }

        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);             // Z1²
        Fp2.Element memory U2 = Fp2.mul(x2, Z1Z1);         // U2 = x2 * Z1²
        Fp2.Element memory S2 = Fp2.mul(y2, Fp2.mul(Z1, Z1Z1)); // S2 = y2 * Z1³

        Fp2.Element memory H = Fp2.sub(U2, X1);             // H = U2 - X1
        Fp2.Element memory HH = Fp2.sqr(H);                 // HH = H²
        Fp2.Element memory I = Fp2.add(HH, HH);             // I = 4*H²
        I = Fp2.add(I, I);
        Fp2.Element memory J = Fp2.mul(H, I);               // J = H * I
        Fp2.Element memory r = Fp2.sub(S2, Y1);             // r = S2 - Y1
        r = Fp2.add(r, r);                                  // r = 2*(S2 - Y1)
        Fp2.Element memory V = Fp2.mul(X1, I);              // V = X1 * I

        // X3 = r² - J - 2*V
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));

        // Y3 = r*(V - X3) - 2*Y1*J
        Fp2.Element memory Y1J = Fp2.mul(Y1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(Y1J, Y1J));

        // Z3 = (Z1+H)² - Z1² - H²
        Z3 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, H)), Z1Z1), HH);
    }

    /// @dev General Jacobian point addition: (X1,Y1,Z1) + (X2,Y2,Z2).
    ///      From https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
    function _g2JacAdd(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1,
        Fp2.Element memory X2,
        Fp2.Element memory Y2,
        Fp2.Element memory Z2
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        // Handle points at infinity
        if (Fp2.isZero(Z1)) {
            return (X2, Y2, Z2);
        }
        if (Fp2.isZero(Z2)) {
            return (X1, Y1, Z1);
        }

        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);             // Z1²
        Fp2.Element memory Z2Z2 = Fp2.sqr(Z2);             // Z2²
        Fp2.Element memory U1 = Fp2.mul(X1, Z2Z2);         // U1 = X1 * Z2²
        Fp2.Element memory U2 = Fp2.mul(X2, Z1Z1);         // U2 = X2 * Z1²
        Fp2.Element memory S1 = Fp2.mul(Y1, Fp2.mul(Z2, Z2Z2)); // S1 = Y1 * Z2³
        Fp2.Element memory S2 = Fp2.mul(Y2, Fp2.mul(Z1, Z1Z1)); // S2 = Y2 * Z1³

        Fp2.Element memory H = Fp2.sub(U2, U1);             // H = U2 - U1
        Fp2.Element memory I = Fp2.add(H, H);               // I = (2H)²
        I = Fp2.sqr(I);
        Fp2.Element memory J = Fp2.mul(H, I);               // J = H * I
        Fp2.Element memory r = Fp2.sub(S2, S1);             // r = S2 - S1
        r = Fp2.add(r, r);                                  // r = 2*(S2 - S1)
        Fp2.Element memory V = Fp2.mul(U1, I);              // V = U1 * I

        // X3 = r² - J - 2*V
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));

        // Y3 = r*(V - X3) - 2*S1*J
        Fp2.Element memory S1J = Fp2.mul(S1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(S1J, S1J));

        // Z3 = ((Z1+Z2)² - Z1² - Z2²) * H
        Z3 = Fp2.mul(
            Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, Z2)), Z1Z1), Z2Z2),
            H
        );
    }

    // ── Homogeneous polynomial evaluation over Fp2 ────────────────

    /// @dev Evaluate polynomial P(N/D) in homogeneous form.
    ///      Returns (num, den) such that P(N/D) = num/den, where den = D^n.
    ///      coeffs are stored high-degree-first: [c_n, c_{n-1}, ..., c_0]
    ///      Uses homogeneous Horner: acc = c_n; for i: D_pow *= D; acc = acc*N + c_i*D_pow
    function _evalPolyHom(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element[] memory coeffs)
        private
        pure
        returns (Fp2.Element memory num, Fp2.Element memory den)
    {
        num = coeffs[0];
        den = Fp2.one();
        for (uint256 i = 1; i < coeffs.length; i++) {
            den = Fp2.mul(den, D);
            num = Fp2.add(Fp2.mul(num, N), Fp2.mul(coeffs[i], den));
        }
    }

    /// @dev Evaluate monic polynomial (leading coeff = 1) in homogeneous form.
    ///      Returns (num, den) such that P(N/D) = num/den, where den = D^n.
    ///      coeffs are stored high-degree-first (without the leading 1): [c_{n-1}, ..., c_0]
    function _evalPolyMonicHom(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element[] memory coeffs)
        private
        pure
        returns (Fp2.Element memory num, Fp2.Element memory den)
    {
        num = Fp2.one();
        den = Fp2.one();
        for (uint256 i = 0; i < coeffs.length; i++) {
            den = Fp2.mul(den, D);
            num = Fp2.add(Fp2.mul(num, N), Fp2.mul(coeffs[i], den));
        }
    }

    // ── Isogenous curve constants ─────────────────────────────────

    /// @dev A' = 0 + 240*i
    function _aPrime() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(new bytes(48), Fp.fromUint256(240));
    }

    /// @dev B' = 1012 + 1012*i
    function _bPrime() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(Fp.fromUint256(1012), Fp.fromUint256(1012));
    }

    /// @dev Z = -(2+i) = -2 - i
    function _z() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(Fp.neg(Fp.fromUint256(2)), Fp.neg(Fp.fromUint256(1)));
    }

    // ── 3-Isogeny coefficient arrays (RFC 9380, Section 8.8.2) ────

    // Helper to create Fp2 element from two hex constants
    function _fp2(bytes memory c0, bytes memory c1) private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(c0, c1);
    }

    // x_num coefficients k_(1,i) for i=3..0, stored HIGH-DEGREE-FIRST
    function _xNumCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](4);
        // k_(1,3)
        c[0] = _fp2(
            hex"171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
            new bytes(48)
        );
        // k_(1,2)
        c[1] = _fp2(
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
            hex"08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"
        );
        // k_(1,1)
        c[2] = _fp2(
            new bytes(48),
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"
        );
        // k_(1,0)
        c[3] = _fp2(
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"
        );
    }

    // x_den coefficients k_(2,i) for i=1..0, stored HIGH-DEGREE-FIRST (monic: x^2 + ...)
    function _xDenCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](2);
        // k_(2,1)
        c[0] = _fp2(
            Fp.fromUint256(12),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"
        );
        // k_(2,0)
        c[1] = _fp2(
            new bytes(48),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"
        );
    }

    // y_num coefficients k_(3,i) for i=3..0, stored HIGH-DEGREE-FIRST
    function _yNumCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](4);
        // k_(3,3)
        c[0] = _fp2(
            hex"124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
            new bytes(48)
        );
        // k_(3,2)
        c[1] = _fp2(
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
            hex"08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"
        );
        // k_(3,1)
        c[2] = _fp2(
            new bytes(48),
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"
        );
        // k_(3,0)
        c[3] = _fp2(
            hex"1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
            hex"1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"
        );
    }

    // y_den coefficients k_(4,i) for i=2..0, stored HIGH-DEGREE-FIRST (monic: x^3 + ...)
    function _yDenCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](3);
        // k_(4,2)
        c[0] = _fp2(
            Fp.fromUint256(18),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"
        );
        // k_(4,1)
        c[1] = _fp2(
            new bytes(48),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"
        );
        // k_(4,0)
        c[2] = _fp2(
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
        );
    }
}
