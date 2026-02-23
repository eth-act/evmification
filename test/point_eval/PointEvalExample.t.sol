// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {PointEvalPrecompile} from "../../src/point_eval/PointEvalPrecompile.sol";
import {PointEval} from "../../src/point_eval/PointEval.sol";

/// @notice External wrapper so vm.expectRevert works with internal library calls.
contract PointEvalCaller {
    function verify(bytes calldata input) external view returns (uint256, uint256) {
        return PointEval.verify(input);
    }
}

contract PointEvalExampleTest is Test {
    PointEvalCaller caller;
    // BLS_MODULUS
    uint256 constant BLS_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    function setUp() public {
        caller = new PointEvalCaller();
    }

    // ── Test vector 1: constant polynomial f(x)=1 ──────────────
    // commitment = G1 generator, proof = point at infinity, z=1, y=1
    bytes constant VALID_INPUT_1 =
        hex"01cf478a431837728dcec3461f4f53b8749cdc4e03496dcaed459dea82b82eb8" // versioned_hash
        hex"0000000000000000000000000000000000000000000000000000000000000001" // z
        hex"0000000000000000000000000000000000000000000000000000000000000001" // y
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb" // commitment
        hex"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"; // proof

    // ── Test vector 2: linear polynomial f(x)=x ────────────────
    // commitment = [τ]₁, proof = G1 generator, z=7, y=7
    bytes constant VALID_INPUT_2 =
        hex"014fa3bb4018340ca2fa8eb239e23af6ba465f6d5bc31db78988445da078db76" // versioned_hash
        hex"0000000000000000000000000000000000000000000000000000000000000007" // z
        hex"0000000000000000000000000000000000000000000000000000000000000007" // y
        hex"ad3eb50121139aa34db1d545093ac9374ab7bca2c0f3bf28e27c8dcd8fc7cb42d25926fc0c97b336e9f0fb35e5a04c81" // commitment
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"; // proof

    // ── Precompile wrapper tests ────────────────────────────────

    function test_precompile_valid_vector1() public view {
        (uint256 fe, uint256 mod) = PointEvalPrecompile.verify(VALID_INPUT_1);
        assertEq(fe, 4096);
        assertEq(mod, BLS_MODULUS);
    }

    function test_precompile_valid_vector2() public view {
        (uint256 fe, uint256 mod) = PointEvalPrecompile.verify(VALID_INPUT_2);
        assertEq(fe, 4096);
        assertEq(mod, BLS_MODULUS);
    }

    // ── BLS implementation tests ────────────────────────────────

    function test_bls_valid_vector1() public view {
        (uint256 fe, uint256 mod) = PointEval.verify(VALID_INPUT_1);
        assertEq(fe, 4096);
        assertEq(mod, BLS_MODULUS);
    }

    function test_bls_valid_vector2() public view {
        (uint256 fe, uint256 mod) = PointEval.verify(VALID_INPUT_2);
        assertEq(fe, 4096);
        assertEq(mod, BLS_MODULUS);
    }

    // ── Invalid versioned hash ──────────────────────────────────

    function test_bls_revert_bad_versioned_hash() public {
        bytes memory input = new bytes(192);
        _copy(input, VALID_INPUT_1);
        // Corrupt byte 1 of versioned hash
        input[1] = bytes1(uint8(input[1]) ^ 0xff);
        vm.expectRevert("bad versioned hash");
        caller.verify(input);
    }

    // ── z out of range ──────────────────────────────────────────

    function test_bls_revert_z_out_of_range() public {
        bytes memory input = new bytes(192);
        _copy(input, VALID_INPUT_1);
        // Set z = BLS_MODULUS (out of range)
        assembly {
            let ptr := add(input, 0x20)
            mstore(add(ptr, 0x20), 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
        }
        vm.expectRevert("z out of range");
        caller.verify(input);
    }

    // ── y out of range ──────────────────────────────────────────

    function test_bls_revert_y_out_of_range() public {
        bytes memory input = new bytes(192);
        _copy(input, VALID_INPUT_1);
        // Set y = BLS_MODULUS (out of range)
        assembly {
            let ptr := add(input, 0x20)
            mstore(add(ptr, 0x40), 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
        }
        vm.expectRevert("y out of range");
        caller.verify(input);
    }

    // ── Differential: precompile vs BLS ─────────────────────────

    function test_differential_vector1() public view {
        (uint256 fe1, uint256 mod1) = PointEvalPrecompile.verify(VALID_INPUT_1);
        (uint256 fe2, uint256 mod2) = PointEval.verify(VALID_INPUT_1);
        assertEq(fe1, fe2, "fieldElementsPerBlob mismatch");
        assertEq(mod1, mod2, "blsModulus mismatch");
    }

    function test_differential_vector2() public view {
        (uint256 fe1, uint256 mod1) = PointEvalPrecompile.verify(VALID_INPUT_2);
        (uint256 fe2, uint256 mod2) = PointEval.verify(VALID_INPUT_2);
        assertEq(fe1, fe2, "fieldElementsPerBlob mismatch");
        assertEq(mod1, mod2, "blsModulus mismatch");
    }

    // ── Helper ──────────────────────────────────────────────────

    function _copy(bytes memory dst, bytes memory src) private pure {
        assembly {
            let len := mload(src)
            let srcPtr := add(src, 0x20)
            let dstPtr := add(dst, 0x20)
            for { let i := 0 } lt(i, len) { i := add(i, 0x20) } {
                mstore(add(dstPtr, i), mload(add(srcPtr, i)))
            }
        }
    }
}
