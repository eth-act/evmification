// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IdentityPrecompile} from "../../src/identity/IdentityPrecompile.sol";
import {Identity} from "../../src/identity/Identity.sol";

contract IdentityExampleTest is Test {
    // ── Precompile known vectors ────────────────────────────────

    function test_identity_empty() public view {
        bytes memory result = IdentityPrecompile.identity("");
        assertEq(result.length, 0);
    }

    function test_identity_hello() public view {
        bytes memory result = IdentityPrecompile.identity("hello");
        assertEq(result, "hello");
    }

    function test_identity_32bytes() public view {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory result = IdentityPrecompile.identity(data);
        assertEq(keccak256(result), keccak256(data));
    }

    function test_identity_256bytes() public view {
        bytes memory data = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory result = IdentityPrecompile.identity(data);
        assertEq(keccak256(result), keccak256(data));
    }

    // ── Pure variant known vectors ──────────────────────────────

    function test_identityPure_empty() public pure {
        bytes memory result = Identity.identity("");
        assertEq(result.length, 0);
    }

    function test_identityPure_hello() public pure {
        bytes memory result = Identity.identity("hello");
        assertEq(result, "hello");
    }

    function test_identityPure_32bytes() public pure {
        bytes memory data = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory result = Identity.identity(data);
        assertEq(keccak256(result), keccak256(data));
    }

    function test_identityPure_256bytes() public pure {
        bytes memory data = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            data[i] = bytes1(uint8(i));
        }
        bytes memory result = Identity.identity(data);
        assertEq(keccak256(result), keccak256(data));
    }

    // ── Differential fuzz: precompile == pure ───────────────────

    function testFuzz_differential(bytes calldata data) public view {
        bytes memory precompileResult = IdentityPrecompile.identity(data);
        bytes memory pureResult = Identity.identity(data);
        assertEq(keccak256(precompileResult), keccak256(pureResult), "identity differential mismatch");
    }
}
