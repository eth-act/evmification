// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Sha256Precompile} from "../../src/sha256/Sha256Precompile.sol";
import {Sha256} from "../../src/sha256/Sha256.sol";

/// @notice Thin wrapper to make precompile library calls external for gas measurement.
contract Sha256PrecompileCaller {
    function hash(bytes calldata data) external view returns (bytes32) {
        return Sha256Precompile.hash(data);
    }
}

/// @notice Thin wrapper to make pure library calls external for gas measurement.
contract Sha256PureCaller {
    function hash(bytes calldata data) external pure returns (bytes32) {
        return Sha256.hash(data);
    }
}

/// @notice Thin wrapper for built-in sha256() for gas measurement.
contract Sha256BuiltinCaller {
    function hash(bytes calldata data) external pure returns (bytes32) {
        return sha256(data);
    }
}

contract Sha256BenchmarkTest is Test {
    Sha256PrecompileCaller precompileCaller;
    Sha256PureCaller pureCaller;
    Sha256BuiltinCaller builtinCaller;

    bytes constant SHORT_INPUT = hex"68656c6c6f"; // "hello"

    function setUp() public {
        precompileCaller = new Sha256PrecompileCaller();
        pureCaller = new Sha256PureCaller();
        builtinCaller = new Sha256BuiltinCaller();
    }

    // ── Short input (5 bytes) ───────────────────────────────────

    function test_sha256_short_precompile() public view {
        bytes32 digest = precompileCaller.hash(SHORT_INPUT);
        assertEq(digest, hex"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    function test_sha256_short_pure() public view {
        bytes32 digest = pureCaller.hash(SHORT_INPUT);
        assertEq(digest, hex"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    function test_sha256_short_builtin() public view {
        bytes32 digest = builtinCaller.hash(SHORT_INPUT);
        assertEq(digest, hex"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    // ── 32-byte input ───────────────────────────────────────────

    function test_sha256_32bytes_precompile() public view {
        bytes memory data = _32byteInput();
        bytes32 digest = precompileCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256_32bytes_pure() public view {
        bytes memory data = _32byteInput();
        bytes32 digest = pureCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256_32bytes_builtin() public view {
        bytes memory data = _32byteInput();
        bytes32 digest = builtinCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    // ── Medium input (~256 bytes) ───────────────────────────────

    function test_sha256_medium_precompile() public view {
        bytes memory data = _mediumInput();
        bytes32 digest = precompileCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256_medium_pure() public view {
        bytes memory data = _mediumInput();
        bytes32 digest = pureCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    function test_sha256_medium_builtin() public view {
        bytes memory data = _mediumInput();
        bytes32 digest = builtinCaller.hash(data);
        assertEq(digest, sha256(data));
    }

    /// @dev Returns 32 bytes: 0x00..0x1f.
    function _32byteInput() private pure returns (bytes memory data) {
        data = new bytes(32);
        assembly {
            mstore(add(data, 0x20), 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)
        }
    }

    /// @dev Returns 256 bytes of 0x42.
    function _mediumInput() private pure returns (bytes memory data) {
        data = new bytes(256);
        assembly {
            let ptr := add(data, 0x20)
            let word := 0x4242424242424242424242424242424242424242424242424242424242424242
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                mstore(add(ptr, i), word)
            }
        }
    }
}
