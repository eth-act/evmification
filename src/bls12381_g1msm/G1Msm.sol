// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";

/// @title G1Msm
/// @notice Pure Solidity implementation of the EIP-2537 G1MSM precompile (address 0x0c).
/// @dev Performs multi-scalar multiplication on BLS12-381 G1 (y^2 = x^3 + 4 over Fp).
///      Input: k * 160 bytes — k pairs of (G1 point, scalar).
///      Output: 128 bytes — one G1 point in EIP-2537 format.
library G1Msm {
    /// @dev BLS12-381 subgroup order r.
    uint256 constant BLS12_381_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @notice Computes the multi-scalar multiplication: sum_i(scalar_i * P_i).
    /// @param input k * 160 bytes: k pairs of (G1 point (128 bytes) || scalar (32 bytes)).
    /// @return output 128 bytes: the resulting G1 point.
    function g1Msm(bytes memory input) internal pure returns (bytes memory output) {
        uint256 len = input.length;
        require(len % 160 == 0, "invalid input length");
        uint256 k = len / 160;

        if (k == 0) {
            output = new bytes(128);
            return output;
        }

        // Accumulate in Jacobian coordinates.
        // Infinity is represented by Z == 0.
        bytes memory rX;
        bytes memory rY;
        bytes memory rZ;
        bool rIsInf = true;

        for (uint256 i = 0; i < k; i++) {
            // Parse point and scalar at offset i*160.
            (bytes memory px, bytes memory py, uint256 scalar) = _parsePair(input, i * 160);

            bool pIsInf = Fp.isZero(px) && Fp.isZero(py);

            // Validate point.
            if (!pIsInf) {
                _checkFieldElement(px);
                _checkFieldElement(py);
                _checkOnCurve(px, py);
            }

            // Reduce scalar mod r.
            scalar = scalar % BLS12_381_R;

            if (pIsInf || scalar == 0) continue;

            // Scalar multiply P_i by scalar using Jacobian double-and-add.
            (bytes memory tX, bytes memory tY, bytes memory tZ) = _scalarMulJac(px, py, scalar);

            // Add to accumulator.
            if (rIsInf) {
                rX = tX;
                rY = tY;
                rZ = tZ;
                rIsInf = false;
            } else {
                (rX, rY, rZ) = _jacAdd(rX, rY, rZ, tX, tY, tZ);
                // Check if result is infinity (Z == 0).
                if (Fp.isZero(rZ)) {
                    rIsInf = true;
                }
            }
        }

        // Convert to affine.
        if (rIsInf) {
            output = new bytes(128);
        } else {
            bytes memory zInv = Fp.inv(rZ);
            bytes memory zInv2 = Fp.sqr(zInv);
            bytes memory x = Fp.mul(rX, zInv2);
            bytes memory y = Fp.mul(rY, Fp.mul(zInv2, zInv));
            output = _encodeG1(x, y);
        }
    }

    // ── Input parsing ─────────────────────────────────────────────────

    /// @dev Parse a (G1 point, scalar) pair from the input at the given byte offset.
    function _parsePair(bytes memory input, uint256 offset)
        private
        pure
        returns (bytes memory px, bytes memory py, uint256 scalar)
    {
        // Validate padding bytes are zero.
        _checkPadding(input, offset);
        _checkPadding(input, offset + 64);

        px = _extractFp(input, offset);
        py = _extractFp(input, offset + 64);

        // Scalar is 32 bytes at offset + 128.
        assembly {
            scalar := mload(add(add(input, 0x20), add(offset, 128)))
        }
    }

    /// @dev Extract a 48-byte field element from a 64-byte block at the given offset.
    function _extractFp(bytes memory input, uint256 offset) private pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            let src := add(add(add(input, 0x20), offset), 16)
            mstore(add(result, 0x20), mload(src))
            mstore(add(result, 0x30), mload(add(src, 16)))
        }
    }

    /// @dev Check that the 16-byte padding at the given 64-byte block offset is all zeros.
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

    /// @dev Check that a point (x, y) is on the curve y^2 = x^3 + 4.
    function _checkOnCurve(bytes memory x, bytes memory y) private pure {
        bytes memory lhs = Fp.sqr(y);
        bytes memory rhs = Fp.add(Fp.mul(Fp.sqr(x), x), Fp.fromUint256(4));
        require(Fp.eq(lhs, rhs), "point not on curve");
    }

    // ── Jacobian scalar multiplication ────────────────────────────────

    /// @dev Compute scalar * P in Jacobian coordinates using double-and-add.
    ///      P = (px, py) is an affine point. Scalar must be non-zero.
    function _scalarMulJac(bytes memory px, bytes memory py, uint256 scalar)
        private
        pure
        returns (bytes memory X, bytes memory Y, bytes memory Z)
    {
        // Start with P in Jacobian: (px, py, 1).
        X = px;
        Y = py;
        Z = Fp.fromUint256(1);

        // Find MSB position.
        uint256 msb = _msb(scalar);

        // Double-and-add from MSB-1 down to 0.
        for (uint256 i = msb; i > 0;) {
            unchecked { --i; }
            (X, Y, Z) = _g1JacDouble(X, Y, Z);
            if ((scalar >> i) & 1 == 1) {
                (X, Y, Z) = _g1JacAddMixed(X, Y, Z, px, py);
            }
        }
    }

    /// @dev Find the position of the most significant bit (0-indexed).
    function _msb(uint256 x) private pure returns (uint256 r) {
        require(x != 0);
        r = 0;
        if (x >= 1 << 128) { r += 128; x >>= 128; }
        if (x >= 1 << 64) { r += 64; x >>= 64; }
        if (x >= 1 << 32) { r += 32; x >>= 32; }
        if (x >= 1 << 16) { r += 16; x >>= 16; }
        if (x >= 1 << 8) { r += 8; x >>= 8; }
        if (x >= 1 << 4) { r += 4; x >>= 4; }
        if (x >= 1 << 2) { r += 2; x >>= 2; }
        if (x >= 1 << 1) { r += 1; }
    }

    // ── Jacobian point doubling (A=0): dbl-2009-l ─────────────────────

    function _g1JacDouble(bytes memory X, bytes memory Y, bytes memory Z)
        private pure returns (bytes memory X3, bytes memory Y3, bytes memory Z3)
    {
        bytes memory A = Fp.sqr(X);
        bytes memory B = Fp.sqr(Y);
        bytes memory C = Fp.sqr(B);
        // D = 2*((X+B)^2 - A - C)
        bytes memory D = Fp.sub(Fp.sub(Fp.sqr(Fp.add(X, B)), A), C);
        D = Fp.add(D, D);
        // E = 3*A
        bytes memory E = Fp.add(A, Fp.add(A, A));
        bytes memory F = Fp.sqr(E);
        // X3 = F - 2*D
        X3 = Fp.sub(F, Fp.add(D, D));
        // Y3 = E*(D - X3) - 8*C
        bytes memory C8 = Fp.add(C, C);
        C8 = Fp.add(C8, C8);
        C8 = Fp.add(C8, C8);
        Y3 = Fp.sub(Fp.mul(E, Fp.sub(D, X3)), C8);
        // Z3 = 2*Y*Z
        Z3 = Fp.mul(Fp.add(Y, Y), Z);
    }

    // ── Jacobian + affine mixed addition: madd-2007-bl ────────────────

    function _g1JacAddMixed(
        bytes memory X1, bytes memory Y1, bytes memory Z1,
        bytes memory x2, bytes memory y2
    ) private pure returns (bytes memory X3, bytes memory Y3, bytes memory Z3) {
        bytes memory Z1Z1 = Fp.sqr(Z1);
        bytes memory U2 = Fp.mul(x2, Z1Z1);
        bytes memory S2 = Fp.mul(y2, Fp.mul(Z1, Z1Z1));
        bytes memory H = Fp.sub(U2, X1);
        bytes memory HH = Fp.sqr(H);
        bytes memory I = Fp.add(HH, HH);
        I = Fp.add(I, I);
        bytes memory J = Fp.mul(H, I);
        bytes memory R = Fp.add(Fp.sub(S2, Y1), Fp.sub(S2, Y1));
        bytes memory V = Fp.mul(X1, I);
        X3 = Fp.sub(Fp.sub(Fp.sqr(R), J), Fp.add(V, V));
        Y3 = Fp.sub(Fp.mul(R, Fp.sub(V, X3)), Fp.mul(Fp.add(Y1, Y1), J));
        Z3 = Fp.sub(Fp.sub(Fp.sqr(Fp.add(Z1, H)), Z1Z1), HH);
    }

    // ── Full Jacobian + Jacobian addition: add-2007-bl ────────────────

    function _jacAdd(
        bytes memory X1, bytes memory Y1, bytes memory Z1,
        bytes memory X2, bytes memory Y2, bytes memory Z2
    ) private pure returns (bytes memory X3, bytes memory Y3, bytes memory Z3) {
        // Handle infinity: Z == 0 means point at infinity.
        if (Fp.isZero(Z1)) return (X2, Y2, Z2);
        if (Fp.isZero(Z2)) return (X1, Y1, Z1);

        bytes memory Z1Z1 = Fp.sqr(Z1);
        bytes memory Z2Z2 = Fp.sqr(Z2);
        bytes memory U1 = Fp.mul(X1, Z2Z2);
        bytes memory U2 = Fp.mul(X2, Z1Z1);
        bytes memory S1 = Fp.mul(Y1, Fp.mul(Z2, Z2Z2));
        bytes memory S2 = Fp.mul(Y2, Fp.mul(Z1, Z1Z1));

        bytes memory H = Fp.sub(U2, U1);
        bytes memory S_diff = Fp.sub(S2, S1);

        // If H == 0 and S_diff == 0, points are equal -> double.
        if (Fp.isZero(H) && Fp.isZero(S_diff)) {
            return _g1JacDouble(X1, Y1, Z1);
        }
        // If H == 0 but S_diff != 0, points are inverses -> infinity.
        if (Fp.isZero(H)) {
            return (Fp.fromUint256(0), Fp.fromUint256(1), Fp.fromUint256(0));
        }

        bytes memory I = Fp.add(H, H);
        I = Fp.sqr(I); // I = (2H)^2
        bytes memory J = Fp.mul(H, I);
        bytes memory r = Fp.add(S_diff, S_diff); // r = 2*(S2-S1)
        bytes memory V = Fp.mul(U1, I);

        // X3 = r^2 - J - 2V
        X3 = Fp.sub(Fp.sub(Fp.sqr(r), J), Fp.add(V, V));
        // Y3 = r*(V - X3) - 2*S1*J
        Y3 = Fp.sub(Fp.mul(r, Fp.sub(V, X3)), Fp.mul(Fp.add(S1, S1), J));
        // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
        Z3 = Fp.mul(Fp.sub(Fp.sub(Fp.sqr(Fp.add(Z1, Z2)), Z1Z1), Z2Z2), H);
    }

    // ── Output encoding ───────────────────────────────────────────────

    /// @dev Encode a G1 point as 128 bytes in EIP-2537 format.
    function _encodeG1(bytes memory x, bytes memory y) private pure returns (bytes memory output) {
        output = new bytes(128);
        assembly {
            let xSrc := add(x, 0x20)
            let dst := add(output, 0x20)
            mstore(add(dst, 16), mload(xSrc))
            mstore(add(dst, 32), mload(add(xSrc, 16)))
            let ySrc := add(y, 0x20)
            mstore(add(dst, 80), mload(ySrc))
            mstore(add(dst, 96), mload(add(ySrc, 16)))
        }
    }
}
