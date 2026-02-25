// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2fDeployed} from "../../src/blake2f/Blake2fDeployed.sol";

/// @dev Tests that Blake2fDeployed is indistinguishable from the 0x09 precompile
///      when called via staticcall with raw EIP-152 input.
contract Blake2fDeployedTest is Test {
    address deployed;

    function setUp() public {
        deployed = address(new Blake2fDeployed());
    }

    /// @dev Build a 213-byte EIP-152 input from structured parameters.
    function _encodeInput(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) internal pure returns (bytes memory input) {
        input = new bytes(213);
        assembly {
            let buf := add(input, 0x20)

            // Rounds: 4 bytes big-endian
            mstore8(buf, shr(24, rounds))
            mstore8(add(buf, 1), shr(16, rounds))
            mstore8(add(buf, 2), shr(8, rounds))
            mstore8(add(buf, 3), rounds)

            function swap64(x) -> r {
                x := and(x, 0xffffffffffffffff)
                x := or(shl(8, and(x, 0x00FF00FF00FF00FF)), shr(8, and(x, 0xFF00FF00FF00FF00)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                r := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
            }

            // h[0..7]: 8 little-endian uint64s at offset 4
            let ptr := add(buf, 4)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                let val := swap64(mload(add(h, mul(i, 0x20))))
                mstore(ptr, shl(192, val))
                ptr := add(ptr, 8)
            }

            // m[0..15]: 16 little-endian uint64s at offset 68
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let val := swap64(mload(add(m, mul(i, 0x20))))
                mstore(ptr, shl(192, val))
                ptr := add(ptr, 8)
            }

            // t[0..1]: 2 little-endian uint64s at offset 196
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                let val := swap64(mload(add(t, mul(i, 0x20))))
                mstore(ptr, shl(192, val))
                ptr := add(ptr, 8)
            }

            // finalBlock: 1 byte at offset 212
            mstore8(add(buf, 212), finalBlock)
        }
    }

    function _callPrecompile(bytes memory input) internal view returns (bool, bytes memory) {
        return address(0x09).staticcall(input);
    }

    function _callDeployed(bytes memory input) internal view returns (bool, bytes memory) {
        return deployed.staticcall(input);
    }

    function test_identical_output_blake2b_abc() public view {
        uint64[8] memory h;
        h[0] = 0x6a09e667f2bdc948;
        h[1] = 0xbb67ae8584caa73b;
        h[2] = 0x3c6ef372fe94f82b;
        h[3] = 0xa54ff53a5f1d36f1;
        h[4] = 0x510e527fade682d1;
        h[5] = 0x9b05688c2b3e6c1f;
        h[6] = 0x1f83d9abfb41bd6b;
        h[7] = 0x5be0cd19137e2179;
        uint64[16] memory m;
        m[0] = 0x0000000000636261;
        uint64[2] memory t;
        t[0] = 3;

        bytes memory input = _encodeInput(12, h, m, t, true);

        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);

        assertTrue(okPre, "precompile failed");
        assertTrue(okDep, "deployed failed");
        assertEq(outDep, outPre, "output mismatch");
    }

    function test_identical_output_zero_rounds() public view {
        uint64[8] memory h;
        uint64[16] memory m;
        uint64[2] memory t;

        bytes memory input = _encodeInput(0, h, m, t, true);

        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);

        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_output_not_final() public view {
        uint64[8] memory h;
        h[0] = 0x6a09e667f2bdc948;
        uint64[16] memory m;
        m[0] = 0x0000000000636261;
        uint64[2] memory t;
        t[0] = 3;

        bytes memory input = _encodeInput(1, h, m, t, false);

        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);

        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function testFuzz_identical_to_precompile(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) public view {
        vm.assume(rounds <= 20);

        bytes memory input = _encodeInput(rounds, h, m, t, finalBlock);

        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);

        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre, "deployed != precompile");
    }
}
