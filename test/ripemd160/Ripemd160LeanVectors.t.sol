// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Ripemd160} from "../../src/ripemd160/Ripemd160.sol";

contract Ripemd160LeanVectorsTest is Test {
    // ── Helper ──────────────────────────────────────────────────────

    function _repeatBytes(bytes1 b, uint256 count) internal pure returns (bytes memory out) {
        out = new bytes(count);
        for (uint256 i = 0; i < count; i++) {
            out[i] = b;
        }
    }

    // ── Vector 1: "abcdefghijklmnopqrstuvwxyz" (26 bytes, official spec) ──

    function test_v1_alphabet_known() public pure {
        bytes20 digest = Ripemd160.hash("abcdefghijklmnopqrstuvwxyz");
        assertEq(digest, bytes20(hex"f71c27109c692c1b56bbdceb5b9d2865b3708dbc"));
    }

    function test_v1_alphabet_diff() public view {
        bytes memory data = "abcdefghijklmnopqrstuvwxyz";
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 2: mixed alpha+digits (62 bytes, 2-block) ───────────

    function test_v2_alphanumeric_known() public pure {
        bytes20 digest = Ripemd160.hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        assertEq(digest, bytes20(hex"b0e20b6e3116640286ed3a87a5713079b21f5189"));
    }

    function test_v2_alphanumeric_diff() public view {
        bytes memory data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 3: "1234567890" x 8 (80 bytes, 2-block) ────────────

    function test_v3_digits80_known() public pure {
        bytes memory data = bytes.concat(
            "1234567890", "1234567890", "1234567890", "1234567890",
            "1234567890", "1234567890", "1234567890", "1234567890"
        );
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"9b752e45573d4b39f4dbd3323cab82bf63326bfb"));
    }

    function test_v3_digits80_diff() public view {
        bytes memory data = bytes.concat(
            "1234567890", "1234567890", "1234567890", "1234567890",
            "1234567890", "1234567890", "1234567890", "1234567890"
        );
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 4: 55 x 'A' (1-block boundary) ─────────────────────

    function test_v4_55A_known() public pure {
        bytes memory data = _repeatBytes(bytes1("A"), 55);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"c4cf09138ab0b859b70c321375557430649190b4"));
    }

    function test_v4_55A_diff() public view {
        bytes memory data = _repeatBytes(bytes1("A"), 55);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 5: 56 x 'A' (2-block boundary, classic padding bug) ─

    function test_v5_56A_known() public pure {
        bytes memory data = _repeatBytes(bytes1("A"), 56);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"6da64c99dd269139248fa73adfb40e19b8722196"));
    }

    function test_v5_56A_diff() public view {
        bytes memory data = _repeatBytes(bytes1("A"), 56);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 6: 63 x 'A' (just under block) ─────────────────────

    function test_v6_63A_known() public pure {
        bytes memory data = _repeatBytes(bytes1("A"), 63);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"438c51d28af9d8c113e4af71787ad4440636eac6"));
    }

    function test_v6_63A_diff() public view {
        bytes memory data = _repeatBytes(bytes1("A"), 63);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 7: 64 x 'A' (exact block) ──────────────────────────

    function test_v7_64A_known() public pure {
        bytes memory data = _repeatBytes(bytes1("A"), 64);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"76b192ac74796f9d41597324bd348fbed13d0ef3"));
    }

    function test_v7_64A_diff() public view {
        bytes memory data = _repeatBytes(bytes1("A"), 64);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 8: 128 x 'A' (3-block) ─────────────────────────────

    function test_v8_128A_known() public pure {
        bytes memory data = _repeatBytes(bytes1("A"), 128);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"e97ff0a6c5089f5c0176fa53c3801b23906ef632"));
    }

    function test_v8_128A_diff() public view {
        bytes memory data = _repeatBytes(bytes1("A"), 128);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }

    // ── Vector 9: 32 x 0x00 (zero bytes) ──────────────────────────

    function test_v9_32zeros_known() public pure {
        bytes memory data = _repeatBytes(bytes1(0x00), 32);
        bytes20 digest = Ripemd160.hash(data);
        assertEq(digest, bytes20(hex"d1a70126ff7a149ca6f9b638db084480440ff842"));
    }

    function test_v9_32zeros_diff() public view {
        bytes memory data = _repeatBytes(bytes1(0x00), 32);
        assertEq(Ripemd160.hash(data), ripemd160(data));
    }
}
