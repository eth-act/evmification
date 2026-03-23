// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {MapFpToG1} from "../../src/bls12381_map_fp_to_g1/MapFpToG1.sol";
import {MapFpToG2} from "../../src/bls12381_map_fp_to_g2/MapFpToG2.sol";
import {G1Add} from "../../src/bls12381_g1add/G1Add.sol";
import {G2Add} from "../../src/bls12381_g2add/G2Add.sol";
import {Fp} from "../../src/bls12381/Fp.sol";

// ── Wrapper contracts (library functions are internal) ──────────────

contract MapFpToG1Caller {
    function mapToG1(bytes calldata input) external pure returns (bytes memory) {
        return MapFpToG1.mapToG1(input);
    }
}

contract MapFpToG2Caller {
    function mapToG2(bytes calldata input) external pure returns (bytes memory) {
        return MapFpToG2.mapToG2(input);
    }
}

contract G1AddCaller {
    function g1Add(bytes calldata input) external pure returns (bytes memory) {
        return G1Add.g1Add(input);
    }
}

contract G2AddCaller {
    function g2Add(bytes calldata input) external pure returns (bytes memory) {
        return G2Add.g2Add(input);
    }
}

// ── Fuzz test contract ──────────────────────────────────────────────

contract BLS12381FuzzTest is Test {
    MapFpToG1Caller g1MapCaller;
    MapFpToG2Caller g2MapCaller;
    G1AddCaller g1AddCaller;
    G2AddCaller g2AddCaller;

    function setUp() public {
        g1MapCaller = new MapFpToG1Caller();
        g2MapCaller = new MapFpToG2Caller();
        g1AddCaller = new G1AddCaller();
        g2AddCaller = new G2AddCaller();
    }

    // ── Input generators ────────────────────────────────────────────

    /// @dev Generate a valid 64-byte MAP_FP_TO_G1 input (field element < p, left-padded to 64 bytes).
    function _makeG1Input(uint256 seed) private pure returns (bytes memory input) {
        input = new bytes(64);
        bytes32 val = keccak256(abi.encodePacked(seed));
        assembly {
            mstore(add(input, 0x40), val) // last 32 bytes of the 64-byte data
        }
        // p starts with 0x1a in byte 0 of the 48-byte representation (byte 16 of 64-byte padded).
        // Mask to 0x0f ensures the value is < p.
        input[16] = bytes1(uint8(input[16]) & 0x0f);
    }

    /// @dev Generate a valid 128-byte MAP_FP_TO_G2 input (two field elements < p).
    function _makeG2Input(uint256 seed) private pure returns (bytes memory input) {
        input = new bytes(128);
        bytes32 v1 = keccak256(abi.encodePacked(seed));
        bytes32 v2 = keccak256(abi.encodePacked(seed, uint256(1)));
        assembly {
            mstore(add(input, 0x40), v1) // end of first 64-byte block
            mstore(add(input, 0x80), v2) // end of second 64-byte block
        }
        input[16] = bytes1(uint8(input[16]) & 0x0f);
        input[80] = bytes1(uint8(input[80]) & 0x0f);
    }

    /// @dev Map a seed to a valid G1 point (128 bytes) using the native precompile 0x10.
    function _mapToG1Native(uint256 seed) private view returns (bytes memory output) {
        bytes memory input = _makeG1Input(seed);
        output = new bytes(128);
        assembly {
            let ok := staticcall(gas(), 0x10, add(input, 0x20), 64, add(output, 0x20), 128)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev Map a seed to a valid G2 point (256 bytes) using the native precompile 0x11.
    function _mapToG2Native(uint256 seed) private view returns (bytes memory output) {
        bytes memory input = _makeG2Input(seed);
        output = new bytes(256);
        assembly {
            let ok := staticcall(gas(), 0x11, add(input, 0x20), 128, add(output, 0x20), 256)
            if iszero(ok) { revert(0, 0) }
        }
    }

    /// @dev Negate a G1 point (negate y coordinate: p - y).
    ///      G1 point is 128 bytes: [16 pad | 48 x | 16 pad | 48 y].
    function _negateG1(bytes memory encoded) private pure returns (bytes memory result) {
        result = new bytes(128);
        // Copy x part (first 64 bytes)
        assembly {
            let dst := add(result, 0x20)
            let src := add(encoded, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 32), mload(add(src, 32)))
        }
        // Extract y (48 bytes at offset 80 = 64 + 16 padding)
        bytes memory y = new bytes(48);
        assembly {
            let src := add(add(encoded, 0x20), 80)
            mstore(add(y, 0x20), mload(src))
            mstore(add(y, 0x30), mload(add(src, 16)))
        }
        // Check if y is zero
        bool yIsZero;
        assembly {
            let lo := mload(add(y, 0x30))
            let raw := mload(add(y, 0x20))
            let hi := shr(128, raw)
            yIsZero := and(iszero(lo), iszero(hi))
        }
        bytes memory negY;
        if (yIsZero) {
            negY = new bytes(48);
        } else {
            negY = Fp.neg(y);
        }
        // Write negY at offset 80 in result (16-byte padding already zero)
        assembly {
            let dst := add(add(result, 0x20), 80)
            mstore(dst, mload(add(negY, 0x20)))
            mstore(add(dst, 16), mload(add(negY, 0x30)))
        }
    }

    /// @dev Negate a G2 point (negate both components of y coordinate).
    ///      G2 point is 256 bytes: [x.c0(64) | x.c1(64) | y.c0(64) | y.c1(64)].
    function _negateG2(bytes memory point) private pure returns (bytes memory result) {
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
        // Extract y.c0 at offset 128, y.c1 at offset 192
        bytes memory yc0 = _extractFp(point, 128);
        bytes memory yc1 = _extractFp(point, 192);
        // Negate both components
        bytes memory nyc0 = _isZeroFp(yc0) ? new bytes(48) : Fp.neg(yc0);
        bytes memory nyc1 = _isZeroFp(yc1) ? new bytes(48) : Fp.neg(yc1);
        // Write back
        _writeFp(result, 128, nyc0);
        _writeFp(result, 192, nyc1);
    }

    /// @dev Extract a 48-byte Fp element from a 64-byte padded block at offset.
    function _extractFp(bytes memory data, uint256 offset) private pure returns (bytes memory fp) {
        fp = new bytes(48);
        assembly {
            let src := add(add(data, 0x20), add(offset, 16))
            let dst := add(fp, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 16), mload(add(src, 16)))
        }
    }

    /// @dev Write a 48-byte Fp element into a 64-byte padded block at offset.
    function _writeFp(bytes memory data, uint256 offset, bytes memory fp) private pure {
        assembly {
            let src := add(fp, 0x20)
            let dst := add(add(data, 0x20), add(offset, 16))
            mstore(dst, mload(src))
            let tail := shl(128, shr(128, mload(add(src, 32))))
            let existing := and(mload(add(dst, 32)), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(dst, 32), or(tail, existing))
        }
    }

    /// @dev Check if a 48-byte Fp element is zero.
    function _isZeroFp(bytes memory fp) private pure returns (bool z) {
        assembly {
            let lo := mload(add(fp, 0x30))
            let hi := shr(128, mload(add(fp, 0x20)))
            z := and(iszero(lo), iszero(hi))
        }
    }

    /// @dev Concatenate two 128-byte G1 points into a 256-byte G1ADD input.
    function _concatG1(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        result = new bytes(256);
        assembly {
            let dst := add(result, 0x20)
            let srcA := add(a, 0x20)
            let srcB := add(b, 0x20)
            mstore(dst, mload(srcA))
            mstore(add(dst, 0x20), mload(add(srcA, 0x20)))
            mstore(add(dst, 0x40), mload(add(srcA, 0x40)))
            mstore(add(dst, 0x60), mload(add(srcA, 0x60)))
            mstore(add(dst, 0x80), mload(srcB))
            mstore(add(dst, 0xa0), mload(add(srcB, 0x20)))
            mstore(add(dst, 0xc0), mload(add(srcB, 0x40)))
            mstore(add(dst, 0xe0), mload(add(srcB, 0x60)))
        }
    }

    /// @dev Concatenate two 256-byte G2 points into a 512-byte G2ADD input.
    function _concatG2(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        result = new bytes(512);
        assembly {
            let dst := add(result, 0x20)
            let srcA := add(a, 0x20)
            let srcB := add(b, 0x20)
            mstore(dst, mload(srcA))
            mstore(add(dst, 0x20), mload(add(srcA, 0x20)))
            mstore(add(dst, 0x40), mload(add(srcA, 0x40)))
            mstore(add(dst, 0x60), mload(add(srcA, 0x60)))
            mstore(add(dst, 0x80), mload(add(srcA, 0x80)))
            mstore(add(dst, 0xa0), mload(add(srcA, 0xa0)))
            mstore(add(dst, 0xc0), mload(add(srcA, 0xc0)))
            mstore(add(dst, 0xe0), mload(add(srcA, 0xe0)))
            mstore(add(dst, 0x100), mload(srcB))
            mstore(add(dst, 0x120), mload(add(srcB, 0x20)))
            mstore(add(dst, 0x140), mload(add(srcB, 0x40)))
            mstore(add(dst, 0x160), mload(add(srcB, 0x60)))
            mstore(add(dst, 0x180), mload(add(srcB, 0x80)))
            mstore(add(dst, 0x1a0), mload(add(srcB, 0xa0)))
            mstore(add(dst, 0x1c0), mload(add(srcB, 0xc0)))
            mstore(add(dst, 0x1e0), mload(add(srcB, 0xe0)))
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // MAP_FP_TO_G1 fuzz tests
    // ═══════════════════════════════════════════════════════════════════

    /// @dev forge-config: default.fuzz.runs = 256
    function testFuzz_mapFpToG1(uint256 seed) public view {
        bytes memory input = _makeG1Input(seed);

        // Native precompile
        (bool ok, bytes memory expected) = address(0x10).staticcall(input);
        require(ok, "MAP_FP_TO_G1 precompile failed");

        // Solidity implementation
        bytes memory actual = g1MapCaller.mapToG1(input);

        assertEq(actual, expected, "MAP_FP_TO_G1 mismatch");
    }

    // ═══════════════════════════════════════════════════════════════════
    // MAP_FP_TO_G2 fuzz tests
    // ═══════════════════════════════════════════════════════════════════

    /// @dev forge-config: default.fuzz.runs = 32
    function testFuzz_mapFpToG2(uint256 seed) public view {
        bytes memory input = _makeG2Input(seed);

        // Native precompile
        (bool ok, bytes memory expected) = address(0x11).staticcall(input);
        require(ok, "MAP_FP_TO_G2 precompile failed");

        // Solidity implementation
        bytes memory actual = g2MapCaller.mapToG2(input);

        assertEq(actual, expected, "MAP_FP_TO_G2 mismatch");
    }

    // ═══════════════════════════════════════════════════════════════════
    // G1ADD fuzz tests
    // ═══════════════════════════════════════════════════════════════════

    /// @dev forge-config: default.fuzz.runs = 256
    function testFuzz_g1Add(uint256 seed1, uint256 seed2) public view {
        // Generate two valid G1 points by mapping field elements to the curve
        bytes memory p1 = _mapToG1Native(seed1);
        bytes memory p2 = _mapToG1Native(seed2);
        bytes memory input = _concatG1(p1, p2);

        // Native precompile
        (bool ok, bytes memory expected) = address(0x0b).staticcall(input);
        require(ok, "G1ADD precompile failed");

        // Solidity implementation
        bytes memory actual = g1AddCaller.g1Add(input);

        assertEq(actual, expected, "G1ADD mismatch");
    }

    /// @dev forge-config: default.fuzz.runs = 256
    function testFuzz_g1AddDoubling(uint256 seed) public view {
        bytes memory p = _mapToG1Native(seed);
        bytes memory input = _concatG1(p, p);

        (bool ok, bytes memory expected) = address(0x0b).staticcall(input);
        require(ok, "G1ADD doubling precompile failed");

        bytes memory actual = g1AddCaller.g1Add(input);

        assertEq(actual, expected, "G1ADD doubling mismatch");
    }

    /// @dev forge-config: default.fuzz.runs = 256
    function testFuzz_g1AddNegation(uint256 seed) public view {
        bytes memory p = _mapToG1Native(seed);
        bytes memory negP = _negateG1(p);
        bytes memory input = _concatG1(p, negP);

        (bool ok, bytes memory expected) = address(0x0b).staticcall(input);
        require(ok, "G1ADD negation precompile failed");

        bytes memory actual = g1AddCaller.g1Add(input);

        // Result should be the point at infinity (128 zero bytes)
        bytes memory infinity = new bytes(128);
        assertEq(expected, infinity, "precompile P+(-P) should be infinity");
        assertEq(actual, expected, "G1ADD negation mismatch");
    }

    // ═══════════════════════════════════════════════════════════════════
    // G2ADD fuzz tests
    // ═══════════════════════════════════════════════════════════════════

    /// @dev forge-config: default.fuzz.runs = 32
    function testFuzz_g2Add(uint256 seed1, uint256 seed2) public view {
        bytes memory p1 = _mapToG2Native(seed1);
        bytes memory p2 = _mapToG2Native(seed2);
        bytes memory input = _concatG2(p1, p2);

        (bool ok, bytes memory expected) = address(0x0d).staticcall(input);
        require(ok, "G2ADD precompile failed");

        bytes memory actual = g2AddCaller.g2Add(input);

        assertEq(actual, expected, "G2ADD mismatch");
    }

    /// @dev forge-config: default.fuzz.runs = 32
    function testFuzz_g2AddDoubling(uint256 seed) public view {
        bytes memory p = _mapToG2Native(seed);
        bytes memory input = _concatG2(p, p);

        (bool ok, bytes memory expected) = address(0x0d).staticcall(input);
        require(ok, "G2ADD doubling precompile failed");

        bytes memory actual = g2AddCaller.g2Add(input);

        assertEq(actual, expected, "G2ADD doubling mismatch");
    }

    /// @dev forge-config: default.fuzz.runs = 32
    function testFuzz_g2AddNegation(uint256 seed) public view {
        bytes memory p = _mapToG2Native(seed);
        bytes memory negP = _negateG2(p);
        bytes memory input = _concatG2(p, negP);

        (bool ok, bytes memory expected) = address(0x0d).staticcall(input);
        require(ok, "G2ADD negation precompile failed");

        bytes memory actual = g2AddCaller.g2Add(input);

        // Result should be the point at infinity (256 zero bytes)
        bytes memory infinity = new bytes(256);
        assertEq(expected, infinity, "precompile P+(-P) should be infinity");
        assertEq(actual, expected, "G2ADD negation mismatch");
    }
}
