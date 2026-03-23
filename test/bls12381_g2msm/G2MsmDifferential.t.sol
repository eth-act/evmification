// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {G2Msm} from "../../src/bls12381_g2msm/G2Msm.sol";
import {G2MsmPrecompile} from "../../src/bls12381_g2msm/G2MsmPrecompile.sol";

contract G2MsmCaller {
    function g2Msm(bytes calldata input) external pure returns (bytes memory) {
        return G2Msm.g2Msm(input);
    }
}

contract G2MsmDifferentialTest is Test {
    G2MsmCaller caller;

    function setUp() public {
        caller = new G2MsmCaller();
    }

    /// @dev Map an Fp2 element to a G2 point using the native MAP_FP_TO_G2 precompile (0x11).
    function _mapToG2(uint256 c0, uint256 c1) private view returns (bytes memory) {
        bytes memory input = new bytes(128);
        assembly {
            let ptr := add(input, 0x20)
            mstore(add(ptr, 0x20), c0)
            mstore(add(ptr, 0x60), c1)
        }
        bytes memory output = new bytes(256);
        assembly {
            let ok := staticcall(gas(), 0x11, add(input, 0x20), 128, add(output, 0x20), 256)
            if iszero(ok) { revert(0, 0) }
        }
        return output;
    }

    /// @dev Call the native G2MSM precompile (0x0e).
    function _nativeG2Msm(bytes memory input) private view returns (bytes memory output) {
        return G2MsmPrecompile.g2Msm(input);
    }

    /// @dev Build a 288-byte MSM chunk: G2_point(256) || scalar(32).
    function _buildChunk(bytes memory point, uint256 scalar) private pure returns (bytes memory chunk) {
        chunk = new bytes(288);
        assembly {
            let dst := add(chunk, 0x20)
            let src := add(point, 0x20)
            // Copy 256 bytes of point
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
            mstore(add(dst, 0x40), mload(add(src, 0x40)))
            mstore(add(dst, 0x60), mload(add(src, 0x60)))
            mstore(add(dst, 0x80), mload(add(src, 0x80)))
            mstore(add(dst, 0xa0), mload(add(src, 0xa0)))
            mstore(add(dst, 0xc0), mload(add(src, 0xc0)))
            mstore(add(dst, 0xe0), mload(add(src, 0xe0)))
            // Write scalar at offset 256
            mstore(add(dst, 0x100), scalar)
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
            for { let i := 0 } lt(i, lenA) { i := add(i, 0x20) } {
                mstore(add(dst, i), mload(add(srcA, i)))
            }
            // Copy b
            let srcB := add(b, 0x20)
            let lenB := mload(b)
            for { let i := 0 } lt(i, lenB) { i := add(i, 0x20) } {
                mstore(add(add(dst, lenA), i), mload(add(srcB, i)))
            }
        }
    }

    // ── Test cases ─────────────────────────────────────────────────

    function test_g2msm_scalar_1() public view {
        bytes memory Q = _mapToG2(1, 2);
        bytes memory input = _buildChunk(Q, 1);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "1*Q mismatch");
    }

    function test_g2msm_scalar_2() public view {
        bytes memory Q = _mapToG2(3, 4);
        bytes memory input = _buildChunk(Q, 2);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "2*Q mismatch");
    }

    function test_g2msm_scalar_7() public view {
        bytes memory Q = _mapToG2(5, 6);
        bytes memory input = _buildChunk(Q, 7);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "7*Q mismatch");
    }

    function test_g2msm_large_scalar() public view {
        bytes memory Q = _mapToG2(7, 8);
        uint256 scalar = 0xdeadbeefcafebabe1234567890abcdef;
        bytes memory input = _buildChunk(Q, scalar);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "large_scalar*Q mismatch");
    }

    function test_g2msm_scalar_0() public view {
        bytes memory Q = _mapToG2(9, 10);
        bytes memory input = _buildChunk(Q, 0);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "0*Q mismatch");
    }

    function test_g2msm_infinity_point() public view {
        bytes memory O = new bytes(256);
        bytes memory input = _buildChunk(O, 5);

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "5*O mismatch");
    }

    function test_g2msm_k2() public view {
        bytes memory Q1 = _mapToG2(11, 12);
        bytes memory Q2 = _mapToG2(13, 14);
        uint256 s1 = 3;
        uint256 s2 = 5;

        bytes memory input = _concat(_buildChunk(Q1, s1), _buildChunk(Q2, s2));

        bytes memory expected = _nativeG2Msm(input);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "3*Q1 + 5*Q2 mismatch");
    }

    function test_g2msm_empty_input() public view {
        bytes memory input = new bytes(0);

        bytes memory expected = new bytes(256);
        bytes memory actual = caller.g2Msm(input);
        assertEq(actual, expected, "empty input mismatch");
    }
}
