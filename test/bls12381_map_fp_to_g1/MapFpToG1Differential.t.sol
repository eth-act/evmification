// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Fp} from "../../src/bls12381/Fp.sol";
import {MapFpToG1} from "../../src/bls12381_map_fp_to_g1/MapFpToG1.sol";
import {MapFpToG1Precompile} from "../../src/bls12381_map_fp_to_g1/MapFpToG1Precompile.sol";

contract MapFpToG1Caller {
    function mapToG1(bytes calldata input) external pure returns (bytes memory) {
        return MapFpToG1.mapToG1(input);
    }
}

contract MapFpToG1DifferentialTest is Test {
    MapFpToG1Caller caller;

    function setUp() public {
        caller = new MapFpToG1Caller();
    }

    // Helper to make a valid 64-byte input from a uint256
    // Layout: 16 zero-pad bytes | 48-byte Fp element (big-endian)
    // In memory: [length(32)] [data(64)] => data starts at input+0x20
    // We want val in the last 32 bytes of data => offset 0x20 + 0x20 = 0x40
    function _makeInput(uint256 val) private pure returns (bytes memory input) {
        input = new bytes(64);
        assembly {
            mstore(add(input, 0x40), val) // last 32 bytes of the 64-byte data
        }
    }

    function test_compute_sqrt_minus_z() public pure {
        // Z = 11 (non-square in Fp). SQRT_MINUS_Z = sqrt(-Z) = sqrt(-11) = sqrt(p - 11).
        bytes memory negEleven = Fp.neg(Fp.fromUint256(11));
        bytes memory sqrtNeg11 = Fp.sqrt(negEleven);
        bytes memory check = Fp.sqr(sqrtNeg11);
        assertEq(keccak256(check), keccak256(negEleven), "sqrt(-11) verification failed");
        // Verify it matches the hardcoded constant
        assertEq(
            keccak256(sqrtNeg11),
            keccak256(hex"04610e003bd3ac94dfa9246c390d7a78942602029175a4ca366d601f33f3946e3ed39794735c38315d874bc1d70637c3"),
            "SQRT_MINUS_Z constant mismatch"
        );
    }

    function test_differential_u_one() public view {
        bytes memory input = _makeInput(1);
        bytes memory expected = MapFpToG1Precompile.mapToG1(input);
        bytes memory actual = caller.mapToG1(input);
        assertEq(actual, expected, "u=1 mismatch");
    }

    function test_differential_u_seven() public view {
        bytes memory input = _makeInput(7);
        bytes memory expected = MapFpToG1Precompile.mapToG1(input);
        bytes memory actual = caller.mapToG1(input);
        assertEq(actual, expected, "u=7 mismatch");
    }

    function test_differential_u_large() public view {
        bytes memory input = new bytes(64);
        // Use a large field element
        input[16] = 0x0d;
        input[17] = 0x54;
        assembly {
            mstore(add(input, 0x40), 0x6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa)
        }
        bytes memory expected = MapFpToG1Precompile.mapToG1(input);
        bytes memory actual = caller.mapToG1(input);
        assertEq(actual, expected, "large input mismatch");
    }
}
