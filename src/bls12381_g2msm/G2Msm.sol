// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";
import {Fp2} from "../bls12381/Fp2.sol";

/// @title G2Msm
/// @notice Pure Solidity implementation of the EIP-2537 G2MSM precompile (address 0x0e).
/// @dev Computes multi-scalar multiplication: sum_i(scalar_i * Q_i) on the BLS12-381 G2 curve.
///      Uses Jacobian coordinates throughout, with a single Fp2.inv at the end for affine conversion.
library G2Msm {
    /// @notice Computes multi-scalar multiplication on G2.
    /// @param input k * 288 bytes: k chunks of (G2_point(256) || scalar(32)).
    /// @return output 256 bytes: the resulting G2 point in EIP-2537 format.
    function g2Msm(bytes memory input) internal pure returns (bytes memory output) {
        uint256 len = input.length;
        require(len % 288 == 0, "invalid input length");
        uint256 k = len / 288;

        if (k == 0) {
            output = new bytes(256);
            return output;
        }

        // Accumulator in Jacobian coords; infinity represented by Z = 0
        Fp2.Element memory accX = Fp2.zero();
        Fp2.Element memory accY = Fp2.zero();
        Fp2.Element memory accZ = Fp2.zero(); // Z=0 => infinity

        for (uint256 i = 0; i < k; i++) {
            uint256 off = i * 288;

            // Parse affine G2 point
            Fp2.Element memory qx = _extractFp2(input, off);
            Fp2.Element memory qy = _extractFp2(input, off + 128);

            // Parse 32-byte big-endian scalar
            uint256 scalar;
            assembly {
                scalar := mload(add(add(input, 0x20), add(off, 256)))
            }

            bool qInf = Fp2.isZero(qx) && Fp2.isZero(qy);

            // Skip if scalar is zero or point is infinity
            if (scalar == 0 || qInf) {
                continue;
            }

            // Scalar multiply: double-and-add in Jacobian
            (Fp2.Element memory rX, Fp2.Element memory rY, Fp2.Element memory rZ) =
                _scalarMulJac(qx, qy, scalar);

            // Accumulate
            (accX, accY, accZ) = _g2JacAdd(accX, accY, accZ, rX, rY, rZ);
        }

        // If result is infinity, return 256 zero bytes
        if (Fp2.isZero(accZ)) {
            return new bytes(256);
        }

        // Convert Jacobian to affine: x = X/Z², y = Y/Z³
        Fp2.Element memory zInv = Fp2.inv(accZ);
        Fp2.Element memory zInv2 = Fp2.sqr(zInv);
        Fp2.Element memory zInv3 = Fp2.mul(zInv2, zInv);

        Fp2.Element memory affX = Fp2.mul(accX, zInv2);
        Fp2.Element memory affY = Fp2.mul(accY, zInv3);

        return _encodeG2(affX, affY);
    }

    // ── Scalar multiplication ──────────────────────────────────────

    /// @dev Double-and-add scalar multiplication of an affine point.
    function _scalarMulJac(
        Fp2.Element memory qx,
        Fp2.Element memory qy,
        uint256 scalar
    )
        private
        pure
        returns (Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
    {
        // Start from infinity
        X = Fp2.zero();
        Y = Fp2.zero();
        Z = Fp2.zero();

        // Find highest bit
        uint256 bit = 255;
        while (bit > 0 && (scalar >> bit) == 0) {
            bit--;
        }

        // Process from highest set bit down to 0
        for (uint256 j = bit + 1; j > 0;) {
            j--;
            // Double
            if (!Fp2.isZero(Z)) {
                (X, Y, Z) = _g2JacDouble(X, Y, Z);
            }

            // Add if bit is set
            if ((scalar >> j) & 1 == 1) {
                if (Fp2.isZero(Z)) {
                    // Accumulator is infinity, set to affine point
                    X = qx;
                    Y = qy;
                    Z = Fp2.one();
                } else {
                    (X, Y, Z) = _g2JacAddMixed(X, Y, Z, qx, qy);
                }
            }
        }
    }

    // ── Jacobian G2 arithmetic ─────────────────────────────────────

    /// @dev Point doubling in Jacobian coordinates for a=0 curve.
    function _g2JacDouble(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        Fp2.Element memory A = Fp2.sqr(X1);          // A = X1^2
        Fp2.Element memory B = Fp2.sqr(Y1);          // B = Y1^2
        Fp2.Element memory C = Fp2.sqr(B);           // C = B^2 = Y1^4

        // D = 2*((X1+B)^2 - A - C)
        Fp2.Element memory t = Fp2.sqr(Fp2.add(X1, B));
        t = Fp2.sub(Fp2.sub(t, A), C);
        Fp2.Element memory D = Fp2.add(t, t);

        // E = 3*A
        Fp2.Element memory E = Fp2.add(A, Fp2.add(A, A));

        Fp2.Element memory F = Fp2.sqr(E);           // F = E^2

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

    /// @dev Mixed addition: Jacobian (X1,Y1,Z1) + affine (x2,y2).
    ///      Assumes the affine point is not infinity.
    ///      Handles the doubling case (H=0, r=0) by falling back to _g2JacDouble.
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

        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);             // Z1^2
        Fp2.Element memory U2 = Fp2.mul(x2, Z1Z1);         // U2 = x2 * Z1^2
        Fp2.Element memory S2 = Fp2.mul(y2, Fp2.mul(Z1, Z1Z1)); // S2 = y2 * Z1^3

        Fp2.Element memory H = Fp2.sub(U2, X1);             // H = U2 - X1

        // If H == 0 the points have the same x-coordinate (in affine)
        if (Fp2.isZero(H)) {
            Fp2.Element memory dy = Fp2.sub(S2, Y1);
            if (Fp2.isZero(dy)) {
                // Same point: double
                return _g2JacDouble(X1, Y1, Z1);
            } else {
                // Inverse points: return infinity
                return (Fp2.zero(), Fp2.zero(), Fp2.zero());
            }
        }

        Fp2.Element memory HH = Fp2.sqr(H);                 // HH = H^2
        Fp2.Element memory I = Fp2.add(HH, HH);             // I = 4*H^2
        I = Fp2.add(I, I);
        Fp2.Element memory J = Fp2.mul(H, I);               // J = H * I
        Fp2.Element memory r = Fp2.sub(S2, Y1);             // r = S2 - Y1
        r = Fp2.add(r, r);                                  // r = 2*(S2 - Y1)
        Fp2.Element memory V = Fp2.mul(X1, I);              // V = X1 * I

        // X3 = r^2 - J - 2*V
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));

        // Y3 = r*(V - X3) - 2*Y1*J
        Fp2.Element memory Y1J = Fp2.mul(Y1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(Y1J, Y1J));

        // Z3 = (Z1+H)^2 - Z1^2 - H^2
        Z3 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, H)), Z1Z1), HH);
    }

    /// @dev General Jacobian addition: (X1,Y1,Z1) + (X2,Y2,Z2).
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

        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);             // Z1^2
        Fp2.Element memory Z2Z2 = Fp2.sqr(Z2);             // Z2^2
        Fp2.Element memory U1 = Fp2.mul(X1, Z2Z2);         // U1 = X1 * Z2^2
        Fp2.Element memory U2 = Fp2.mul(X2, Z1Z1);         // U2 = X2 * Z1^2
        Fp2.Element memory S1 = Fp2.mul(Y1, Fp2.mul(Z2, Z2Z2)); // S1 = Y1 * Z2^3
        Fp2.Element memory S2 = Fp2.mul(Y2, Fp2.mul(Z1, Z1Z1)); // S2 = Y2 * Z1^3

        Fp2.Element memory H = Fp2.sub(U2, U1);             // H = U2 - U1

        // If H == 0 the points have the same x-coordinate
        if (Fp2.isZero(H)) {
            Fp2.Element memory dy = Fp2.sub(S2, S1);
            if (Fp2.isZero(dy)) {
                // Same point: double
                return _g2JacDouble(X1, Y1, Z1);
            } else {
                // Inverse points: return infinity
                return (Fp2.zero(), Fp2.zero(), Fp2.zero());
            }
        }

        Fp2.Element memory I = Fp2.add(H, H);               // I = (2H)^2
        I = Fp2.sqr(I);
        Fp2.Element memory J = Fp2.mul(H, I);               // J = H * I
        Fp2.Element memory r = Fp2.sub(S2, S1);             // r = S2 - S1
        r = Fp2.add(r, r);                                  // r = 2*(S2 - S1)
        Fp2.Element memory V = Fp2.mul(U1, I);              // V = U1 * I

        // X3 = r^2 - J - 2*V
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));

        // Y3 = r*(V - X3) - 2*S1*J
        Fp2.Element memory S1J = Fp2.mul(S1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(S1J, S1J));

        // Z3 = ((Z1+Z2)^2 - Z1^2 - Z2^2) * H
        Z3 = Fp2.mul(
            Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, Z2)), Z1Z1), Z2Z2),
            H
        );
    }

    // ── Encoding / Decoding ────────────────────────────────────────

    /// @dev Extract an Fp2 element from two consecutive 64-byte blocks at the given offset.
    ///      Each 64-byte block: 16-byte zero-pad + 48-byte Fp element.
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
            // c1: at offset+64, skip 16-byte padding, copy 48 bytes
            let c1Src := add(src, 80) // 64 + 16
            let c1Dst := add(c1, 0x20)
            mstore(c1Dst, mload(c1Src))
            mstore(add(c1Dst, 16), mload(add(c1Src, 16)))
        }
        return Fp2.Element(c0, c1);
    }

    /// @dev Encode an Fp2 G2 point (x, y) into 256 bytes of EIP-2537 format.
    function _encodeG2(Fp2.Element memory x, Fp2.Element memory y) private pure returns (bytes memory output) {
        output = new bytes(256);
        _encodeFp(output, 0, x.c0);
        _encodeFp(output, 64, x.c1);
        _encodeFp(output, 128, y.c0);
        _encodeFp(output, 192, y.c1);
    }

    /// @dev Write a 48-byte Fp element into a 64-byte block (16-byte zero-pad + 48-byte data).
    function _encodeFp(bytes memory output, uint256 blockOffset, bytes memory fp) private pure {
        assembly {
            let dst := add(add(output, 0x20), blockOffset)
            let src := add(fp, 0x20)
            mstore(add(dst, 16), mload(src))
            let tail := shl(128, shr(128, mload(add(src, 32))))
            let existing := and(mload(add(dst, 48)), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(dst, 48), or(tail, existing))
        }
    }
}
