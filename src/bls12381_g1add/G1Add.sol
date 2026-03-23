// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";

/// @title G1Add
/// @notice Pure Solidity implementation of the EIP-2537 G1ADD precompile (address 0x0b).
/// @dev Performs elliptic curve addition on BLS12-381 G1 (y^2 = x^3 + 4 over Fp).
///      Input: 256 bytes — two G1 points, each 128 bytes (16-zero-pad | x(48) | 16-zero-pad | y(48)).
///      Output: 128 bytes — one G1 point in the same format.
library G1Add {
    /// @notice Adds two G1 points.
    /// @param input 256 bytes: two G1 points in EIP-2537 encoding.
    /// @return output 128 bytes: the resulting G1 point.
    function g1Add(bytes memory input) internal pure returns (bytes memory output) {
        require(input.length == 256, "invalid input length");

        // Parse field elements from EIP-2537 encoding.
        // Each 64-byte block: 16-byte zero padding || 48-byte Fp element.
        bytes memory x1 = _extractFp(input, 0);
        bytes memory y1 = _extractFp(input, 64);
        bytes memory x2 = _extractFp(input, 128);
        bytes memory y2 = _extractFp(input, 192);

        // Validate padding bytes are zero.
        _checkPadding(input, 0);
        _checkPadding(input, 64);
        _checkPadding(input, 128);
        _checkPadding(input, 192);

        // Validate coordinates are less than p.
        _checkFieldElement(x1);
        _checkFieldElement(y1);
        _checkFieldElement(x2);
        _checkFieldElement(y2);

        bool inf1 = Fp.isZero(x1) && Fp.isZero(y1);
        bool inf2 = Fp.isZero(x2) && Fp.isZero(y2);

        // Validate points are on the curve (unless point at infinity).
        if (!inf1) _checkOnCurve(x1, y1);
        if (!inf2) _checkOnCurve(x2, y2);

        // Handle point at infinity cases.
        if (inf1 && inf2) return new bytes(128);
        if (inf1) return _encodeG1(x2, y2);
        if (inf2) return _encodeG1(x1, y1);

        // Compute slope (lambda).
        bytes memory lam;
        if (Fp.eq(x1, x2)) {
            if (!Fp.eq(y1, y2)) {
                // P == -Q: return point at infinity.
                return new bytes(128);
            }
            // P == Q: point doubling.
            // lambda = 3*x1^2 / (2*y1)
            bytes memory x1sq = Fp.sqr(x1);
            bytes memory num = Fp.add(Fp.add(x1sq, x1sq), x1sq); // 3*x1^2
            bytes memory den = Fp.add(y1, y1); // 2*y1
            lam = Fp.mul(num, Fp.inv(den));
        } else {
            // General addition: lambda = (y2 - y1) / (x2 - x1)
            lam = Fp.mul(Fp.sub(y2, y1), Fp.inv(Fp.sub(x2, x1)));
        }

        // x3 = lambda^2 - x1 - x2
        bytes memory xr = Fp.sub(Fp.sub(Fp.sqr(lam), x1), x2);
        // y3 = lambda*(x1 - x3) - y1
        bytes memory yr = Fp.sub(Fp.mul(lam, Fp.sub(x1, xr)), y1);

        return _encodeG1(xr, yr);
    }

    /// @dev Extract a 48-byte field element from a 64-byte block at the given offset.
    ///      Layout: input[offset..offset+16] = zero padding, input[offset+16..offset+64] = Fp element.
    function _extractFp(bytes memory input, uint256 offset) private pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // Source: input + 0x20 (skip length) + offset + 16 (skip padding)
            let src := add(add(add(input, 0x20), offset), 16)
            // Copy 48 bytes (two 32-byte reads, but second is only 16 bytes)
            mstore(add(result, 0x20), mload(src))
            mstore(add(result, 0x30), mload(add(src, 16)))
        }
    }

    /// @dev Check that the 16-byte padding at the given 64-byte block offset is all zeros.
    function _checkPadding(bytes memory input, uint256 offset) private pure {
        bool valid;
        assembly {
            let src := add(add(input, 0x20), offset)
            // Load 32 bytes at src; the first 16 bytes must be zero.
            let word := mload(src)
            valid := iszero(shr(128, word))
        }
        require(valid, "non-zero padding");
    }

    /// @dev Check that a 48-byte value is less than the field modulus p.
    function _checkFieldElement(bytes memory a) private pure {
        bool valid;
        assembly {
            // Load a as (aHi:128, aLo:256)
            let aLen := mload(a)
            let aLo := mload(add(a, add(0x20, sub(aLen, 32))))
            let hiBytes := sub(aLen, 32)
            let aHi := shr(mul(sub(32, hiBytes), 8), mload(add(a, 0x20)))

            let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
            let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab

            // a < p iff (aHi < pHi) or (aHi == pHi and aLo < pLo)
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

    /// @dev Encode a G1 point as 128 bytes in EIP-2537 format.
    ///      Layout: 16-zero-pad || x(48) || 16-zero-pad || y(48).
    function _encodeG1(bytes memory x, bytes memory y) private pure returns (bytes memory output) {
        output = new bytes(128);
        assembly {
            // x: copy 48 bytes to output[16..64]
            let xSrc := add(x, 0x20)
            let dst := add(output, 0x20) // output data start
            // output[16..48] = first 32 bytes of x
            mstore(add(dst, 16), mload(xSrc))
            // output[48..64] = next 16 bytes of x (bytes 32..48)
            mstore(add(dst, 32), mload(add(xSrc, 16)))

            // y: copy 48 bytes to output[80..128]
            let ySrc := add(y, 0x20)
            mstore(add(dst, 80), mload(ySrc))
            mstore(add(dst, 96), mload(add(ySrc, 16)))
        }
    }
}
