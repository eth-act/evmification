// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";
import {Fp2} from "../bls12381/Fp2.sol";

/// @title G2Add
/// @notice Pure Solidity implementation of the EIP-2537 G2ADD precompile (address 0x0d).
/// @dev Performs point addition on the BLS12-381 G2 curve E2: y^2 = x^3 + 4(1+i) over Fp2.
library G2Add {
    /// @notice Adds two G2 points.
    /// @param input 512 bytes: two G2 points, each 256 bytes in EIP-2537 format.
    /// @return output 256 bytes: the resulting G2 point.
    function g2Add(bytes memory input) internal pure returns (bytes memory output) {
        require(input.length == 512, "invalid input length");

        // Parse two G2 points
        Fp2.Element memory x1 = _extractFp2(input, 0);
        Fp2.Element memory y1 = _extractFp2(input, 128);
        Fp2.Element memory x2 = _extractFp2(input, 256);
        Fp2.Element memory y2 = _extractFp2(input, 384);

        bool inf1 = Fp2.isZero(x1) && Fp2.isZero(y1);
        bool inf2 = Fp2.isZero(x2) && Fp2.isZero(y2);

        // Identity cases
        if (inf1 && inf2) return new bytes(256);
        if (inf1) return _encodeG2(x2, y2);
        if (inf2) return _encodeG2(x1, y1);

        Fp2.Element memory lam;
        Fp2.Element memory x3;
        Fp2.Element memory y3;

        // Same x-coordinate
        if (Fp2.eq(x1, x2)) {
            if (Fp2.eq(y1, y2)) {
                // Doubling: lambda = 3*x1^2 / (2*y1)   (a=0 for E2)
                Fp2.Element memory x1sq = Fp2.sqr(x1);
                Fp2.Element memory three = Fp2.fromFp(Fp.fromUint256(3), new bytes(48));
                Fp2.Element memory num = Fp2.mul(three, x1sq);
                Fp2.Element memory two = Fp2.fromFp(Fp.fromUint256(2), new bytes(48));
                Fp2.Element memory den = Fp2.mul(two, y1);
                lam = Fp2.mul(num, Fp2.inv(den));

                x3 = Fp2.sub(Fp2.sqr(lam), Fp2.mul(two, x1));
                y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(x1, x3)), y1);

                return _encodeG2(x3, y3);
            }
            // P + (-P) = O
            return new bytes(256);
        }

        // General addition: lambda = (y2-y1) / (x2-x1)
        lam = Fp2.mul(Fp2.sub(y2, y1), Fp2.inv(Fp2.sub(x2, x1)));

        x3 = Fp2.sub(Fp2.sub(Fp2.sqr(lam), x1), x2);
        y3 = Fp2.sub(Fp2.mul(lam, Fp2.sub(x1, x3)), y1);

        return _encodeG2(x3, y3);
    }

    /// @dev Extract an Fp2 element from two consecutive 64-byte blocks at the given offset.
    ///      Each 64-byte block: 16-byte zero-pad + 48-byte Fp element.
    function _extractFp2(bytes memory input, uint256 offset) private pure returns (Fp2.Element memory) {
        bytes memory c0 = new bytes(48);
        bytes memory c1 = new bytes(48);
        assembly {
            let src := add(add(input, 0x20), offset)
            // c0: skip 16-byte padding, copy 48 bytes (offset + 16)
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
        // x.c0 at offset 0: 16-byte padding + 48 bytes
        // x.c1 at offset 64: 16-byte padding + 48 bytes
        // y.c0 at offset 128: 16-byte padding + 48 bytes
        // y.c1 at offset 192: 16-byte padding + 48 bytes
        _encodeFp(output, 0, x.c0);
        _encodeFp(output, 64, x.c1);
        _encodeFp(output, 128, y.c0);
        _encodeFp(output, 192, y.c1);
    }

    /// @dev Write a 48-byte Fp element into a 64-byte block (16-byte zero-pad + 48-byte data)
    ///      at the given offset in the output buffer, without overflowing into the next block.
    function _encodeFp(bytes memory output, uint256 blockOffset, bytes memory fp) private pure {
        assembly {
            let dst := add(add(output, 0x20), blockOffset)
            let src := add(fp, 0x20)
            // Write first 32 bytes of Fp at dst+16 (after 16-byte zero pad)
            mstore(add(dst, 16), mload(src))
            // Write last 16 bytes of Fp at dst+48
            // We need to write exactly 16 bytes without touching dst+64 onward.
            // Load 32 bytes from src+32 (only first 16 are valid Fp data).
            // Shift left by 128 bits to get the 16 valid bytes into the high half.
            // Load existing 32 bytes at dst+48, mask to keep low 16 bytes,
            // OR with the shifted value.
            let tail := shl(128, shr(128, mload(add(src, 32))))
            let existing := and(mload(add(dst, 48)), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(dst, 48), or(tail, existing))
        }
    }
}
