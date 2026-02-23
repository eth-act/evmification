// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2b} from "../../examples/blake2f/Blake2b.sol";
import {Blake2bPure} from "../../examples/blake2f/Blake2bPure.sol";

contract Blake2bExampleTest is Test {
    // ── BLAKE2b-256 known vectors ──────────────────────────────

    function test_blake2b256_empty() public view {
        bytes memory digest = Blake2b.hash("", 32);
        assertEq(digest, hex"0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
    }

    function test_blake2b256_abc() public view {
        bytes memory digest = Blake2b.hash("abc", 32);
        assertEq(digest, hex"bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
    }

    function test_blake2b256_hello() public view {
        bytes memory digest = Blake2b.hash("hello", 32);
        assertEq(digest, hex"324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf");
    }

    // ── BLAKE2b-512 known vectors ──────────────────────────────

    function test_blake2b512_empty() public view {
        bytes memory digest = Blake2b.hash("", 64);
        assertEq(
            digest,
            hex"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    function test_blake2b512_abc() public view {
        bytes memory digest = Blake2b.hash("abc", 64);
        assertEq(
            digest,
            hex"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    // ── Multi-block (>128 bytes) ───────────────────────────────

    function test_blake2b256_multiblock() public view {
        // 256 bytes: 0x00..0xff
        bytes memory data = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory digest = Blake2b.hash(data, 32);
        assertEq(digest, hex"39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835");
    }

    function test_blake2b512_multiblock() public view {
        bytes memory data = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory digest = Blake2b.hash(data, 64);
        assertEq(
            digest,
            hex"1ecc896f34d3f9cac484c73f75f6a5fb58ee6784be41b35f46067b9c65c63a6794d3d744112c653f73dd7deb6666204c5a9bfa5b46081fc10fdbe7884fa5cbf8"
        );
    }

    // ── Pure variant known vectors ─────────────────────────────

    function test_blake2bPure256_hello() public pure {
        bytes memory digest = Blake2bPure.hash("hello", 32);
        assertEq(digest, hex"324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf");
    }

    function test_blake2bPure512_abc() public pure {
        bytes memory digest = Blake2bPure.hash("abc", 64);
        assertEq(
            digest,
            hex"ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    // ── Differential: precompile matches pure ──────────────────

    function testFuzz_differential_blake2b256(bytes calldata data) public view {
        bytes memory precompileResult = Blake2b.hash(data, 32);
        bytes memory pureResult = Blake2bPure.hash(data, 32);
        assertEq(precompileResult, pureResult, "blake2b-256 differential mismatch");
    }

    function testFuzz_differential_blake2b512(bytes calldata data) public view {
        bytes memory precompileResult = Blake2b.hash(data, 64);
        bytes memory pureResult = Blake2bPure.hash(data, 64);
        assertEq(precompileResult, pureResult, "blake2b-512 differential mismatch");
    }
}
