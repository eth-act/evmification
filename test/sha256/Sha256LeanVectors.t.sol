// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Sha256} from "../../src/sha256/Sha256.sol";

contract Sha256LeanVectorsTest is Test {
    // ── Helper ──────────────────────────────────────────────────────

    function _repeatBytes(bytes1 b, uint256 count) internal pure returns (bytes memory) {
        bytes memory data = new bytes(count);
        for (uint256 i = 0; i < count; i++) {
            data[i] = b;
        }
        return data;
    }

    // ── 1. Single byte "a" ──────────────────────────────────────────

    function test_1_singleByte() public pure {
        bytes32 digest = Sha256.hash("a");
        assertEq(digest, hex"ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    }

    function test_1_singleByte_differential() public view {
        bytes memory data = bytes("a");
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 2. 55 x 'a' — max single-block ─────────────────────────────

    function test_2_55a() public pure {
        bytes memory data = _repeatBytes(0x61, 55);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    }

    function test_2_55a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 55);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 3. 56 x 'a' — classic padding boundary ─────────────────────

    function test_3_56a() public pure {
        bytes memory data = _repeatBytes(0x61, 56);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    }

    function test_3_56a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 56);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 4. 63 x 'a' — one short of block ───────────────────────────

    function test_4_63a() public pure {
        bytes memory data = _repeatBytes(0x61, 63);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34");
    }

    function test_4_63a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 63);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 5. 64 x 'a' — exact block ──────────────────────────────────

    function test_5_64a() public pure {
        bytes memory data = _repeatBytes(0x61, 64);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    }

    function test_5_64a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 64);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 6. 119 x 'a' — max two-block ───────────────────────────────

    function test_6_119a() public pure {
        bytes memory data = _repeatBytes(0x61, 119);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb");
    }

    function test_6_119a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 119);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 7. 120 x 'a' — forces third block ──────────────────────────

    function test_7_120a() public pure {
        bytes memory data = _repeatBytes(0x61, 120);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c");
    }

    function test_7_120a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 120);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 8. 128 x 'a' — multi-block ─────────────────────────────────

    function test_8_128a() public pure {
        bytes memory data = _repeatBytes(0x61, 128);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e");
    }

    function test_8_128a_differential() public view {
        bytes memory data = _repeatBytes(0x61, 128);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 9. NIST 896-bit (112 bytes) ────────────────────────────────

    function test_9_nist896() public pure {
        bytes memory data = bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    }

    function test_9_nist896_differential() public view {
        bytes memory data = bytes("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu");
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 10. 55 x 0x00 — zeros at boundary ──────────────────────────

    function test_10_55zeros() public pure {
        bytes memory data = _repeatBytes(0x00, 55);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7");
    }

    function test_10_55zeros_differential() public view {
        bytes memory data = _repeatBytes(0x00, 55);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 11. 56 x 0x00 — zeros at 2-block boundary ──────────────────

    function test_11_56zeros() public pure {
        bytes memory data = _repeatBytes(0x00, 56);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb");
    }

    function test_11_56zeros_differential() public view {
        bytes memory data = _repeatBytes(0x00, 56);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 12. 64 x 0x00 — full block zeros ───────────────────────────

    function test_12_64zeros() public pure {
        bytes memory data = _repeatBytes(0x00, 64);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    }

    function test_12_64zeros_differential() public view {
        bytes memory data = _repeatBytes(0x00, 64);
        assertEq(Sha256.hash(data), sha256(data));
    }

    // ── 13. 32 x 0xFF — all-ones ───────────────────────────────────

    function test_13_32ones() public pure {
        bytes memory data = _repeatBytes(0xFF, 32);
        bytes32 digest = Sha256.hash(data);
        assertEq(digest, hex"af9613760f72635fbdb44a5a0a63c39f12af30f950a6ee5c971be188e89c4051");
    }

    function test_13_32ones_differential() public view {
        bytes memory data = _repeatBytes(0xFF, 32);
        assertEq(Sha256.hash(data), sha256(data));
    }
}
