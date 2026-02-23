// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Ripemd160Precompile} from "../../src/ripemd160/Ripemd160Precompile.sol";
import {Ripemd160} from "../../src/ripemd160/Ripemd160.sol";

contract Ripemd160ExampleTest is Test {
    // ── Precompile known vectors ────────────────────────────────

    function test_ripemd160_empty() public view {
        bytes20 digest = Ripemd160Precompile.hash("");
        assertEq(digest, bytes20(hex"9c1185a5c5e9fc54612808977ee8f548b2258d31"));
    }

    function test_ripemd160_abc() public view {
        bytes20 digest = Ripemd160Precompile.hash("abc");
        assertEq(digest, bytes20(hex"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
    }

    function test_ripemd160_hello() public view {
        bytes20 digest = Ripemd160Precompile.hash("hello");
        assertEq(digest, bytes20(hex"108f07b8382412612c048d07d13f814118445acd"));
    }

    function test_ripemd160_multiblock() public view {
        // 80 bytes (> 64, forces 2 blocks)
        bytes memory data = new bytes(80);
        for (uint256 i = 0; i < 80; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes20 digest = Ripemd160Precompile.hash(data);
        assertEq(digest, ripemd160(data));
    }

    function test_ripemd160_32bytes() public view {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes20 digest = Ripemd160Precompile.hash(data);
        assertEq(digest, ripemd160(data));
    }

    // ── Cross-check precompile wrapper against built-in ripemd160() ──

    function test_ripemd160_precompile_matches_builtin_empty() public view {
        assertEq(Ripemd160Precompile.hash(""), ripemd160(""));
    }

    function test_ripemd160_precompile_matches_builtin_abc() public view {
        assertEq(Ripemd160Precompile.hash("abc"), ripemd160("abc"));
    }

    // ── Pure variant known vectors ──────────────────────────────

    function test_ripemd160Pure_empty() public pure {
        bytes20 digest = Ripemd160.hash("");
        assertEq(digest, bytes20(hex"9c1185a5c5e9fc54612808977ee8f548b2258d31"));
    }

    function test_ripemd160Pure_abc() public pure {
        bytes20 digest = Ripemd160.hash("abc");
        assertEq(digest, bytes20(hex"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
    }

    function test_ripemd160Pure_hello() public pure {
        bytes20 digest = Ripemd160.hash("hello");
        assertEq(digest, bytes20(hex"108f07b8382412612c048d07d13f814118445acd"));
    }

    function test_ripemd160Pure_multiblock() public view {
        bytes memory data = new bytes(80);
        for (uint256 i = 0; i < 80; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, ripemd160(data));
    }

    function test_ripemd160Pure_32bytes() public view {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, ripemd160(data));
    }

    // ── Differential fuzz: precompile == pure ───────────────────

    function testFuzz_differential(bytes calldata data) public view {
        bytes20 precompileResult = Ripemd160Precompile.hash(data);
        bytes20 pureResult = Ripemd160.hash(data);
        assertEq(precompileResult, pureResult, "ripemd160 differential mismatch");
    }
}
