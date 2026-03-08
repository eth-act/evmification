// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Modexp} from "../modexp/Modexp.sol";

/// @title BLS12381
/// @notice Low-level helpers for BLS12-381 operations via EIP-2537 precompiles.
library BLS12381 {
    // ── BLS12-381 constants ─────────────────────────────────────

    /// @dev Base field modulus p.
    bytes constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    /// @dev (p + 1) / 4, used for modular square root (since p ≡ 3 mod 4).
    bytes constant P_PLUS_1_DIV_4 =
        hex"0680447a8e5ff9a692c6e9ed90d2eb35d91dd2e13ce144afd9cc34a83dac3d8907aaffffac54ffffee7fbfffffffeaab";

    /// @dev Scalar field modulus r (BLS_MODULUS in EIP-4844).
    uint256 constant BLS_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    /// @dev TAU_G2: [τ]₂ from KZG trusted setup (g2_monomial[1]), pre-decompressed to EIP-2537 format.
    ///      256 bytes: x_c0(64) || x_c1(64) || y_c0(64) || y_c1(64).
    bytes constant TAU_G2 =
        hex"00000000000000000000000000000000185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2"
        hex"0000000000000000000000000000000015bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72"
        hex"00000000000000000000000000000000014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99"
        hex"000000000000000000000000000000001666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f";

    /// @dev G2 generator in EIP-2537 format (256 bytes).
    bytes constant G2_GEN =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // ── EIP-2537 precompile addresses ───────────────────────────

    address constant G1ADD  = address(0x0b);
    address constant G1MSM  = address(0x0c);
    address constant G2ADD  = address(0x0d);
    address constant G2MSM  = address(0x0e);
    address constant PAIRING = address(0x0f);

    // ── G1 decompression ────────────────────────────────────────

    /// @notice Decompress a 48-byte compressed G1 point to 128-byte EIP-2537 format.
    /// @param compressed 48-byte BLS compressed G1 point.
    /// @return point 128-byte uncompressed point (x padded to 64 || y padded to 64).
    function decompressG1(bytes memory compressed) internal view returns (bytes memory point) {
        require(compressed.length == 48, "invalid G1 length");

        uint8 flagByte;
        assembly { flagByte := byte(0, mload(add(compressed, 0x20))) }

        bool isInfinity = (flagByte & 0x40) != 0;
        if (isInfinity) {
            point = new bytes(128);
            return point;
        }

        bool ySign = (flagByte & 0x20) != 0;

        // Clear flag bits to get x coordinate
        bytes memory xBytes = new bytes(48);
        assembly {
            let src := add(compressed, 0x20)
            let dst := add(xBytes, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }
        // Clear top 3 bits of first byte
        assembly {
            let ptr := add(xBytes, 0x20)
            let first := byte(0, mload(ptr))
            first := and(first, 0x1f)
            mstore8(ptr, first)
        }

        // Compute y² = x³ + 4 mod p
        bytes memory x3 = Modexp.modexp(xBytes, hex"03", P);
        // x³ + 4 mod p
        bytes memory ySq = _addmod(x3, hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004", P);

        // y = y²^((p+1)/4) mod p
        bytes memory yBytes = Modexp.modexp(ySq, P_PLUS_1_DIV_4, P);

        // Verify y² ≡ ySq (square y back)
        bytes memory ySquaredCheck = Modexp.modexp(yBytes, hex"02", P);
        require(keccak256(ySquaredCheck) == keccak256(ySq), "not on curve");

        // Check sign: if y > (p-1)/2, it's the "large" root
        bool yIsLarge = _isLargerThanHalfP(yBytes);
        if (yIsLarge != ySign) {
            yBytes = _submod(P, yBytes);
        }

        // Pack into 128 bytes: 16-zero-pad || x(48) || 16-zero-pad || y(48)
        point = new bytes(128);
        assembly {
            let dst := add(point, 0x20)
            let xSrc := add(xBytes, 0x20)
            let ySrc := add(yBytes, 0x20)
            // x at offset 16 (first 16 bytes are zero)
            mstore(add(dst, 0x10), mload(xSrc))
            mstore(add(dst, 0x30), mload(add(xSrc, 0x20)))
            // y at offset 80 (64 + 16)
            mstore(add(dst, 0x50), mload(ySrc))
            mstore(add(dst, 0x70), mload(add(ySrc, 0x20)))
        }
    }

    // ── G1 operations ───────────────────────────────────────────

    /// @notice Negate a G1 point: (x, y) → (x, p − y).
    function negateG1(bytes memory point) internal pure returns (bytes memory result) {
        require(point.length == 128, "invalid G1 point length");
        result = new bytes(128);

        // Copy x (first 64 bytes)
        assembly {
            let src := add(point, 0x20)
            let dst := add(result, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }

        // Check if point is infinity (all zeros)
        bool isZero;
        assembly {
            let src := add(point, 0x20)
            isZero := iszero(or(or(mload(src), mload(add(src, 0x20))), or(mload(add(src, 0x40)), mload(add(src, 0x60)))))
        }
        if (isZero) return result;

        // Extract y (48 bytes at offset 80, i.e. bytes 64..128, but actual value at 80..128)
        bytes memory yBytes = new bytes(48);
        assembly {
            let src := add(point, 0x20)
            let dst := add(yBytes, 0x20)
            mstore(dst, mload(add(src, 0x50)))
            mstore(add(dst, 0x20), mload(add(src, 0x70)))
        }

        // p - y
        bytes memory negY = _submod(P, yBytes);

        // Write negated y at offset 64 (16-zero-pad || negY(48))
        assembly {
            let dst := add(result, 0x20)
            let src := add(negY, 0x20)
            mstore(add(dst, 0x50), mload(src))
            mstore(add(dst, 0x70), mload(add(src, 0x20)))
        }
    }

    /// @notice Add two G1 points via the G1ADD precompile (0x0b).
    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(a, b);
        result = new bytes(128);
        assembly {
            let success := staticcall(gas(), 0x0b, add(input, 0x20), 256, add(result, 0x20), 128)
            if iszero(success) { revert(0, 0) }
        }
    }

    /// @notice Scalar multiply a G1 point via G1MSM precompile (0x0c) with k=1.
    function g1Mul(bytes memory point, bytes32 scalar) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(point, scalar);
        result = new bytes(128);
        assembly {
            let success := staticcall(gas(), 0x0c, add(input, 0x20), 160, add(result, 0x20), 128)
            if iszero(success) { revert(0, 0) }
        }
    }

    // ── G2 operations ───────────────────────────────────────────

    /// @notice Negate a G2 point: negate both Fp components of the y-coordinate.
    function negateG2(bytes memory point) internal pure returns (bytes memory result) {
        require(point.length == 256, "invalid G2 point length");
        result = new bytes(256);

        // Copy x (first 128 bytes)
        assembly {
            let src := add(point, 0x20)
            let dst := add(result, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
            mstore(add(dst, 0x40), mload(add(src, 0x40)))
            mstore(add(dst, 0x60), mload(add(src, 0x60)))
        }

        // Check if point is infinity (all zeros)
        bool isZero;
        assembly {
            let src := add(point, 0x20)
            let acc := or(or(mload(src), mload(add(src, 0x20))), or(mload(add(src, 0x40)), mload(add(src, 0x60))))
            acc := or(acc, or(or(mload(add(src, 0x80)), mload(add(src, 0xa0))), or(mload(add(src, 0xc0)), mload(add(src, 0xe0)))))
            isZero := iszero(acc)
        }
        if (isZero) return result;

        // Extract y_c0 (48 bytes at offset 128+16=144)
        bytes memory yC0 = new bytes(48);
        assembly {
            let src := add(point, 0x20)
            let dst := add(yC0, 0x20)
            mstore(dst, mload(add(src, 0x90)))
            mstore(add(dst, 0x20), mload(add(src, 0xb0)))
        }
        // Extract y_c1 (48 bytes at offset 192+16=208)
        bytes memory yC1 = new bytes(48);
        assembly {
            let src := add(point, 0x20)
            let dst := add(yC1, 0x20)
            mstore(dst, mload(add(src, 0xd0)))
            mstore(add(dst, 0x20), mload(add(src, 0xf0)))
        }

        // Negate: p - y_c0, p - y_c1
        bytes memory negYC0 = _submod(P, yC0);
        bytes memory negYC1 = _submod(P, yC1);

        // Write negated y coordinates
        assembly {
            let dst := add(result, 0x20)
            let c0Src := add(negYC0, 0x20)
            let c1Src := add(negYC1, 0x20)
            // y_c0 at offset 128 (16-zero-pad || 48 bytes)
            mstore(add(dst, 0x90), mload(c0Src))
            mstore(add(dst, 0xb0), mload(add(c0Src, 0x20)))
            // y_c1 at offset 192 (16-zero-pad || 48 bytes)
            mstore(add(dst, 0xd0), mload(c1Src))
            mstore(add(dst, 0xf0), mload(add(c1Src, 0x20)))
        }
    }

    /// @notice Add two G2 points via the G2ADD precompile (0x0d).
    function g2Add(bytes memory a, bytes memory b) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(a, b);
        result = new bytes(256);
        assembly {
            let success := staticcall(gas(), 0x0d, add(input, 0x20), 512, add(result, 0x20), 256)
            if iszero(success) { revert(0, 0) }
        }
    }

    /// @notice Scalar multiply a G2 point via G2MSM precompile (0x0e) with k=1.
    function g2Mul(bytes memory point, bytes32 scalar) internal view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(point, scalar);
        result = new bytes(256);
        assembly {
            let success := staticcall(gas(), 0x0e, add(input, 0x20), 288, add(result, 0x20), 256)
            if iszero(success) { revert(0, 0) }
        }
    }

    // ── Pairing ─────────────────────────────────────────────────

    /// @notice BLS12-381 pairing check via precompile (0x0f).
    /// @param pairs Concatenated pairs, each 384 bytes (G1 128 || G2 256).
    /// @return ok True if the pairing product equals 1.
    function pairing(bytes memory pairs) internal view returns (bool ok) {
        assembly {
            let outBuf := mload(0x40)
            let success := staticcall(gas(), 0x0f, add(pairs, 0x20), mload(pairs), outBuf, 0x20)
            if iszero(success) { revert(0, 0) }
            ok := mload(outBuf)
        }
    }

    // ── Internal helpers ────────────────────────────────────────

    /// @dev Compute (a + b) mod m for 48-byte big-endian values, using modexp identity: (a+b) mod m.
    function _addmod(bytes memory a, bytes memory b, bytes memory m) private view returns (bytes memory) {
        // a + b might overflow 48 bytes, so we do it in 49 bytes
        bytes memory sum = _addBytes(a, b);
        // Reduce mod m via modexp(sum, 1, m)
        return Modexp.modexp(sum, hex"01", m);
    }

    /// @dev Big-endian byte addition. Returns result that may be 1 byte longer than inputs.
    function _addBytes(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        uint256 lenA = a.length;
        uint256 lenB = b.length;
        uint256 maxLen = lenA > lenB ? lenA : lenB;
        result = new bytes(maxLen + 1);

        uint256 carry;
        for (uint256 i = 0; i < maxLen; i++) {
            uint256 digitA = i < lenA ? uint8(a[lenA - 1 - i]) : 0;
            uint256 digitB = i < lenB ? uint8(b[lenB - 1 - i]) : 0;
            uint256 sum = digitA + digitB + carry;
            result[maxLen - i] = bytes1(uint8(sum & 0xff));
            carry = sum >> 8;
        }
        result[0] = bytes1(uint8(carry));
    }

    /// @dev Compute m - a for 48-byte values (assumes a < m and a != 0).
    function _submod(bytes memory m, bytes memory a) private pure returns (bytes memory result) {
        result = new bytes(48);
        assembly {
            // Load as (hi: 16 bytes, lo: 32 bytes) big-endian
            let mLo := mload(add(m, 0x30))
            let mHi := shr(128, mload(add(m, 0x20)))
            let aLen := mload(a)
            let aLo
            let aHi
            if gt(aLen, 31) {
                aLo := mload(add(a, add(0x20, sub(aLen, 32))))
                aHi := shr(128, mload(add(a, 0x20)))
            }
            if lt(aLen, 32) {
                // Short value: load from end, right-aligned
                aLo := mload(add(a, add(0x20, sub(aLen, min(aLen, 32)))))
                if lt(aLen, 32) { aLo := shr(mul(sub(32, aLen), 8), aLo) }
            }
            if eq(aLen, 32) { aLo := mload(add(a, 0x20)) }

            function min(x, y) -> z { z := y if lt(x, y) { z := x } }

            let rLo := sub(mLo, aLo)
            let borrow := gt(aLo, mLo)
            let rHi := sub(sub(mHi, aHi), borrow)

            // Write result: hi first, then lo overwrites lower portion
            mstore(add(result, 0x20), shl(128, rHi))
            mstore(add(result, 0x30), rLo)
        }
    }

    /// @dev Check if a 48-byte big-endian value is > (p-1)/2.
    function _isLargerThanHalfP(bytes memory val) private pure returns (bool result) {
        // (p-1)/2 = 0x0d0088f51cbff34d258dd3db21a5d66b | b23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555
        uint256 halfPHi = 0x0d0088f51cbff34d258dd3db21a5d66b;
        uint256 halfPLo = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;
        assembly {
            let vHi := shr(128, mload(add(val, 0x20)))
            let vLo := mload(add(val, 0x30))
            // Compare hi first, then lo
            result := or(gt(vHi, halfPHi), and(eq(vHi, halfPHi), gt(vLo, halfPLo)))
        }
    }
}
