// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Sha256Precompile} from "../../src/sha256/Sha256Precompile.sol";
import {Sha256} from "../../src/sha256/Sha256.sol";

contract Sha256ExampleTest is Test {
    // ── Precompile known vectors ────────────────────────────────

    function test_sha256_empty() public view {
        bytes32 digest = Sha256Precompile.hash("");
        assertEq(digest, hex"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    function test_sha256_abc() public view {
        bytes32 digest = Sha256Precompile.hash("abc");
        assertEq(digest, hex"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    function test_sha256_hello() public view {
        bytes32 digest = Sha256Precompile.hash("hello");
        assertEq(digest, hex"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    function test_sha256_multiblock() public view {
        // 80 bytes (> 64, forces 2 blocks)
        bytes memory data = new bytes(80);
        for (uint256 i = 0; i < 80; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes32 digest = Sha256Precompile.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256_32bytes() public view {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes32 digest = Sha256Precompile.hash(data);
        assertEq(digest, sha256(data));
    }

    // ── Cross-check precompile wrapper against built-in sha256() ──

    function test_sha256_precompile_matches_builtin_empty() public view {
        assertEq(Sha256Precompile.hash(""), sha256(""));
    }

    function test_sha256_precompile_matches_builtin_abc() public view {
        assertEq(Sha256Precompile.hash("abc"), sha256("abc"));
    }

    // ── Pure variant known vectors ──────────────────────────────

    function test_sha256Pure_empty() public pure {
        bytes32 digest = Sha256.hash("");
        assertEq(digest, hex"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    function test_sha256Pure_abc() public pure {
        bytes32 digest = Sha256.hash("abc");
        assertEq(digest, hex"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    function test_sha256Pure_hello() public pure {
        bytes32 digest = Sha256.hash("hello");
        assertEq(digest, hex"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    function test_sha256Pure_multiblock() public view {
        bytes memory data = new bytes(80);
        for (uint256 i = 0; i < 80; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256Pure_32bytes() public view {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, sha256(data));
    }

    // ── Differential fuzz: precompile == pure ───────────────────

    function testFuzz_differential(bytes calldata data) public view {
        bytes32 precompileResult = Sha256Precompile.hash(data);
        bytes32 pureResult = Sha256.hash(data);
        assertEq(precompileResult, pureResult, "sha256 differential mismatch");
    }

    // ── Differential: precompile == built-in sha256() ───────────

    function testFuzz_precompile_vs_builtin(bytes calldata data) public view {
        bytes32 precompileResult = Sha256Precompile.hash(data);
        bytes32 builtinResult = sha256(data);
        assertEq(precompileResult, builtinResult, "sha256 precompile vs builtin mismatch");
    }
}
