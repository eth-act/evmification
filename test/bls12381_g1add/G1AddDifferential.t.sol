// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {G1Add} from "../../src/bls12381_g1add/G1Add.sol";
import {G1AddPrecompile} from "../../src/bls12381_g1add/G1AddPrecompile.sol";
import {MapFpToG1Precompile} from "../../src/bls12381_map_fp_to_g1/MapFpToG1Precompile.sol";

contract G1AddCaller {
    function g1Add(bytes calldata input) external pure returns (bytes memory) {
        return G1Add.g1Add(input);
    }
}

contract G1AddDifferentialTest is Test {
    G1AddCaller caller;

    // G1 generator point
    bytes constant G1_X = hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_Y = hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    function setUp() public {
        caller = new G1AddCaller();
    }

    /// @dev Encode a G1 point (48-byte x, 48-byte y) into 128-byte EIP-2537 format.
    function _encodePoint(bytes memory x, bytes memory y) private pure returns (bytes memory result) {
        result = new bytes(128);
        assembly {
            let dst := add(result, 0x20)
            // x at offset 16
            mstore(add(dst, 16), mload(add(x, 0x20)))
            mstore(add(dst, 32), mload(add(x, 0x30)))
            // y at offset 80
            mstore(add(dst, 80), mload(add(y, 0x20)))
            mstore(add(dst, 96), mload(add(y, 0x30)))
        }
    }

    /// @dev Build 256-byte input from two encoded G1 points (128 bytes each).
    function _buildInput(bytes memory p1, bytes memory p2) private pure returns (bytes memory result) {
        result = new bytes(256);
        assembly {
            let dst := add(result, 0x20)
            let src1 := add(p1, 0x20)
            let src2 := add(p2, 0x20)
            // Copy p1 (128 bytes = 4 words)
            mstore(dst, mload(src1))
            mstore(add(dst, 32), mload(add(src1, 32)))
            mstore(add(dst, 64), mload(add(src1, 64)))
            mstore(add(dst, 96), mload(add(src1, 96)))
            // Copy p2 (128 bytes = 4 words)
            mstore(add(dst, 128), mload(src2))
            mstore(add(dst, 160), mload(add(src2, 32)))
            mstore(add(dst, 192), mload(add(src2, 64)))
            mstore(add(dst, 224), mload(add(src2, 96)))
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

    /// @dev Compute 2*G using the native precompile (G + G).
    function _doubleG() private view returns (bytes memory) {
        bytes memory g = _generator();
        bytes memory input = _buildInput(g, g);
        return G1AddPrecompile.g1Add(input);
    }

    /// @dev Negate a G1 point (negate y coordinate: p - y).
    function _negatePoint(bytes memory encoded) private pure returns (bytes memory result) {
        result = new bytes(128);
        // Copy x part (first 64 bytes)
        assembly {
            let dst := add(result, 0x20)
            let src := add(encoded, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 32), mload(add(src, 32)))
        }
        // Extract y, negate it, write back
        bytes memory y = new bytes(48);
        assembly {
            let src := add(add(encoded, 0x20), 80) // offset 64 + 16 padding
            mstore(add(y, 0x20), mload(src))
            mstore(add(y, 0x30), mload(add(src, 16)))
        }
        // p - y
        bytes memory negY;
        // Check if y is zero
        bool yIsZero;
        assembly {
            let lo := mload(add(y, 0x30))
            let raw := mload(add(y, 0x20))
            let hi := shr(128, raw)
            yIsZero := and(iszero(lo), iszero(hi))
        }
        if (yIsZero) {
            negY = new bytes(48);
        } else {
            negY = new bytes(48);
            assembly {
                let pHi := 0x1a0111ea397fe69a4b1ba7b6434bacd7
                let pLo := 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
                let yLo := mload(add(y, 0x30))
                let yHi := shr(128, mload(add(y, 0x20)))
                let rLo := sub(pLo, yLo)
                let borrow := gt(yLo, pLo)
                let rHi := sub(sub(pHi, yHi), borrow)
                mstore(add(negY, 0x20), shl(128, rHi))
                mstore(add(negY, 0x30), rLo)
            }
        }
        // Write negY at offset 80 in result
        assembly {
            let dst := add(add(result, 0x20), 80)
            mstore(dst, mload(add(negY, 0x20)))
            mstore(add(dst, 16), mload(add(negY, 0x30)))
        }
    }

    // ── Test cases ──────────────────────────────────────────────────

    function test_two_known_points() public view {
        bytes memory g = _generator();
        bytes memory twoG = _doubleG();
        bytes memory input = _buildInput(g, twoG);

        bytes memory expected = G1AddPrecompile.g1Add(input);
        bytes memory actual = caller.g1Add(input);
        assertEq(actual, expected, "G + 2G mismatch");
    }

    function test_infinity_plus_P() public view {
        bytes memory g = _generator();
        bytes memory inf = _infinity();
        bytes memory input = _buildInput(inf, g);

        bytes memory actual = caller.g1Add(input);
        assertEq(actual, g, "O + P should equal P");
    }

    function test_P_plus_infinity() public view {
        bytes memory g = _generator();
        bytes memory inf = _infinity();
        bytes memory input = _buildInput(g, inf);

        bytes memory actual = caller.g1Add(input);
        assertEq(actual, g, "P + O should equal P");
    }

    function test_infinity_plus_infinity() public view {
        bytes memory inf = _infinity();
        bytes memory input = _buildInput(inf, inf);

        bytes memory actual = caller.g1Add(input);
        assertEq(actual, inf, "O + O should equal O");
    }

    function test_doubling() public view {
        bytes memory g = _generator();
        bytes memory input = _buildInput(g, g);

        bytes memory expected = G1AddPrecompile.g1Add(input);
        bytes memory actual = caller.g1Add(input);
        assertEq(actual, expected, "G + G (doubling) mismatch");
    }

    function test_P_plus_negP() public view {
        bytes memory g = _generator();
        bytes memory negG = _negatePoint(g);
        bytes memory input = _buildInput(g, negG);

        bytes memory actual = caller.g1Add(input);
        bytes memory inf = _infinity();
        assertEq(actual, inf, "P + (-P) should equal O");
    }

    function test_fuzz_differential(uint256 u1, uint256 u2) public view {
        // Bound to valid non-zero field elements (< p, but uint256 fits in lower 256 bits of p)
        u1 = bound(u1, 1, type(uint128).max);
        u2 = bound(u2, 1, type(uint128).max);

        // Map to curve via native precompile to get valid G1 points.
        bytes memory fpInput1 = new bytes(64);
        assembly { mstore(add(fpInput1, 0x40), u1) }
        bytes memory p1 = MapFpToG1Precompile.mapToG1(fpInput1);

        bytes memory fpInput2 = new bytes(64);
        assembly { mstore(add(fpInput2, 0x40), u2) }
        bytes memory p2 = MapFpToG1Precompile.mapToG1(fpInput2);

        bytes memory input = _buildInput(p1, p2);

        bytes memory expected = G1AddPrecompile.g1Add(input);
        bytes memory actual = caller.g1Add(input);
        assertEq(actual, expected, "fuzz differential mismatch");
    }
}
