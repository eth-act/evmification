// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {MapFpToG2} from "../../src/bls12381_map_fp_to_g2/MapFpToG2.sol";
import {MapFpToG2Precompile} from "../../src/bls12381_map_fp_to_g2/MapFpToG2Precompile.sol";

contract MapFpToG2Caller {
    function mapToG2(bytes calldata input) external pure returns (bytes memory) {
        return MapFpToG2.mapToG2(input);
    }
}

contract MapFpToG2DifferentialTest is Test {
    MapFpToG2Caller caller;

    function setUp() public {
        caller = new MapFpToG2Caller();
    }

    // Helper: make 128-byte input from two uint256 values (c0 and c1 of Fp2)
    function _makeInput(uint256 c0, uint256 c1) private pure returns (bytes memory input) {
        input = new bytes(128);
        assembly {
            let ptr := add(input, 0x20)
            // c0: 16 zero-byte padding (already zero) + 48 byte field element
            // put c0 at offset 32 (end of first 64-byte block)
            mstore(add(ptr, 0x20), c0)
            // c1: at offset 64+32 = 96
            mstore(add(ptr, 0x60), c1)
        }
    }

    function test_differential_one_zero() public view {
        bytes memory input = _makeInput(1, 0);
        bytes memory expected = MapFpToG2Precompile.mapToG2(input);
        bytes memory actual = caller.mapToG2(input);
        assertEq(actual, expected, "1+0i mismatch");
    }

    function test_differential_zero_one() public view {
        bytes memory input = _makeInput(0, 1);
        bytes memory expected = MapFpToG2Precompile.mapToG2(input);
        bytes memory actual = caller.mapToG2(input);
        assertEq(actual, expected, "0+1i mismatch");
    }

    function test_differential_seven_three() public view {
        bytes memory input = _makeInput(7, 3);
        bytes memory expected = MapFpToG2Precompile.mapToG2(input);
        bytes memory actual = caller.mapToG2(input);
        assertEq(actual, expected, "7+3i mismatch");
    }
}
