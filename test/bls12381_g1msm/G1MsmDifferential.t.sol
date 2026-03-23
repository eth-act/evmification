// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {G1Msm} from "../../src/bls12381_g1msm/G1Msm.sol";
import {G1MsmPrecompile} from "../../src/bls12381_g1msm/G1MsmPrecompile.sol";
import {MapFpToG1Precompile} from "../../src/bls12381_map_fp_to_g1/MapFpToG1Precompile.sol";

contract G1MsmCaller {
    function g1Msm(bytes calldata input) external pure returns (bytes memory) {
        return G1Msm.g1Msm(input);
    }
}

contract G1MsmDifferentialTest is Test {
    G1MsmCaller caller;

    // G1 generator point
    bytes constant G1_X = hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_Y = hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    function setUp() public {
        caller = new G1MsmCaller();
    }

    // ── Helpers ───────────────────────────────────────────────────────

    /// @dev Encode a G1 point (48-byte x, 48-byte y) into 128-byte EIP-2537 format.
    function _encodePoint(bytes memory x, bytes memory y) private pure returns (bytes memory result) {
        result = new bytes(128);
        assembly {
            let dst := add(result, 0x20)
            mstore(add(dst, 16), mload(add(x, 0x20)))
            mstore(add(dst, 32), mload(add(x, 0x30)))
            mstore(add(dst, 80), mload(add(y, 0x20)))
            mstore(add(dst, 96), mload(add(y, 0x30)))
        }
    }

    /// @dev Build a single MSM pair: G1 point (128 bytes) || scalar (32 bytes) = 160 bytes.
    function _buildPair(bytes memory point, uint256 scalar) private pure returns (bytes memory result) {
        result = new bytes(160);
        assembly {
            let dst := add(result, 0x20)
            let src := add(point, 0x20)
            // Copy 128-byte point (4 words)
            mstore(dst, mload(src))
            mstore(add(dst, 32), mload(add(src, 32)))
            mstore(add(dst, 64), mload(add(src, 64)))
            mstore(add(dst, 96), mload(add(src, 96)))
            // Scalar at offset 128
            mstore(add(dst, 128), scalar)
        }
    }

    /// @dev Concatenate two byte arrays.
    function _concat(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        result = new bytes(a.length + b.length);
        assembly {
            let dst := add(result, 0x20)
            let srcA := add(a, 0x20)
            let lenA := mload(a)
            // Copy a
            for { let i := 0 } lt(i, lenA) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(srcA, i)))
            }
            // Copy b
            let srcB := add(b, 0x20)
            let lenB := mload(b)
            for { let i := 0 } lt(i, lenB) { i := add(i, 32) } {
                mstore(add(add(dst, lenA), i), mload(add(srcB, i)))
            }
        }
    }

    /// @dev Get the G1 generator as 128-byte encoded point.
    function _generator() private pure returns (bytes memory) {
        return _encodePoint(G1_X, G1_Y);
    }

    /// @dev Get the point at infinity as 128 zero bytes.
    function _infinity() private pure returns (bytes memory) {
        return new bytes(128);
    }

    /// @dev Generate a valid G1 point from a field element using the native MAP_FP_TO_G1.
    function _mapToG1(uint256 u) private view returns (bytes memory) {
        bytes memory fpInput = new bytes(64);
        assembly { mstore(add(fpInput, 0x40), u) }
        return MapFpToG1Precompile.mapToG1(fpInput);
    }

    // ── Test cases ────────────────────────────────────────────────────

    function test_k0_empty_input() public {
        bytes memory input = new bytes(0);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, new bytes(128), "k=0 should return infinity");
    }

    function test_k1_scalar_1() public view {
        bytes memory g = _generator();
        bytes memory input = _buildPair(g, 1);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "1*G mismatch");
        // 1*G should be G itself
        assertEq(actual, g, "1*G should equal G");
    }

    function test_k1_scalar_2() public view {
        bytes memory g = _generator();
        bytes memory input = _buildPair(g, 2);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "2*G mismatch");
    }

    function test_k1_scalar_7() public view {
        bytes memory g = _generator();
        bytes memory input = _buildPair(g, 7);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "7*G mismatch");
    }

    function test_k1_large_scalar() public view {
        bytes memory g = _generator();
        uint256 scalar = 0xdeadbeefcafebabe1234567890abcdef;
        bytes memory input = _buildPair(g, scalar);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "large scalar mismatch");
    }

    function test_k1_scalar_0() public view {
        bytes memory g = _generator();
        bytes memory input = _buildPair(g, 0);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "0*G should return infinity");
        assertEq(actual, new bytes(128), "0*G should be zero bytes");
    }

    function test_k1_infinity_point() public view {
        bytes memory inf = _infinity();
        bytes memory input = _buildPair(inf, 42);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "scalar*infinity should return infinity");
        assertEq(actual, new bytes(128), "scalar*infinity should be zero bytes");
    }

    function test_k2_two_generators() public view {
        bytes memory g = _generator();
        // 3*G + 5*G should equal 8*G
        bytes memory input = _concat(_buildPair(g, 3), _buildPair(g, 5));

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "3G+5G mismatch");

        // Also check that it equals 8*G
        bytes memory eightG = G1MsmPrecompile.g1Msm(_buildPair(g, 8));
        assertEq(actual, eightG, "3G+5G should equal 8G");
    }

    function test_k2_different_points() public view {
        bytes memory p1 = _mapToG1(1);
        bytes memory p2 = _mapToG1(2);
        bytes memory input = _concat(_buildPair(p1, 7), _buildPair(p2, 11));

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "k=2 different points mismatch");
    }

    function test_k2_one_zero_scalar() public view {
        bytes memory p1 = _mapToG1(1);
        bytes memory p2 = _mapToG1(2);
        bytes memory input = _concat(_buildPair(p1, 0), _buildPair(p2, 5));

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "k=2 one zero scalar mismatch");
    }

    function test_k3_mixed() public view {
        bytes memory g = _generator();
        bytes memory p1 = _mapToG1(42);
        bytes memory inf = _infinity();
        bytes memory input = _concat(_concat(_buildPair(g, 10), _buildPair(p1, 20)), _buildPair(inf, 30));

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "k=3 mixed mismatch");
    }

    function test_fuzz_k1(uint256 u, uint256 scalar) public view {
        u = bound(u, 1, type(uint128).max);
        scalar = bound(scalar, 1, type(uint128).max);

        bytes memory p = _mapToG1(u);
        bytes memory input = _buildPair(p, scalar);

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "fuzz k=1 mismatch");
    }

    function test_fuzz_k2(uint256 u1, uint256 u2, uint256 s1, uint256 s2) public view {
        u1 = bound(u1, 1, type(uint128).max);
        u2 = bound(u2, 1, type(uint128).max);
        s1 = bound(s1, 1, type(uint64).max);
        s2 = bound(s2, 1, type(uint64).max);

        bytes memory p1 = _mapToG1(u1);
        bytes memory p2 = _mapToG1(u2);
        bytes memory input = _concat(_buildPair(p1, s1), _buildPair(p2, s2));

        bytes memory expected = G1MsmPrecompile.g1Msm(input);
        bytes memory actual = caller.g1Msm(input);
        assertEq(actual, expected, "fuzz k=2 mismatch");
    }
}
