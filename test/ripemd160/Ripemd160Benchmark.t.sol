// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Ripemd160Precompile} from "../../src/ripemd160/Ripemd160Precompile.sol";
import {Ripemd160} from "../../src/ripemd160/Ripemd160.sol";

/// @notice Thin wrapper to make precompile library calls external for gas measurement.
contract Ripemd160PrecompileCaller {
    function hash(bytes calldata data) external view returns (bytes20) {
        return Ripemd160Precompile.hash(data);
    }
}

/// @notice Thin wrapper to make pure library calls external for gas measurement.
contract Ripemd160PureCaller {
    function hash(bytes calldata data) external pure returns (bytes20) {
        return Ripemd160.hash(data);
    }
}

contract Ripemd160BenchmarkTest is Test {
    Ripemd160PrecompileCaller precompileCaller;
    Ripemd160PureCaller pureCaller;

    bytes constant SHORT_INPUT = hex"68656c6c6f"; // "hello"

    function setUp() public {
        precompileCaller = new Ripemd160PrecompileCaller();
        pureCaller = new Ripemd160PureCaller();
    }

    // ── Short input (5 bytes) ───────────────────────────────────

    function test_ripemd160_short_precompile() public view {
        bytes20 digest = precompileCaller.hash(SHORT_INPUT);
        assertEq(digest, bytes20(hex"108f07b8382412612c048d07d13f814118445acd"));
    }

    function test_ripemd160_short_pure() public view {
        bytes20 digest = pureCaller.hash(SHORT_INPUT);
        assertEq(digest, bytes20(hex"108f07b8382412612c048d07d13f814118445acd"));
    }

    // ── 32-byte input ───────────────────────────────────────────

    function test_ripemd160_32bytes_precompile() public view {
        bytes memory data = _32byteInput();
        bytes20 digest = precompileCaller.hash(data);
        assertEq(digest, ripemd160(data));
    }

    function test_ripemd160_32bytes_pure() public view {
        bytes memory data = _32byteInput();
        bytes20 digest = pureCaller.hash(data);
        assertEq(digest, ripemd160(data));
    }

    // ── Medium input (~256 bytes) ───────────────────────────────

    function test_ripemd160_medium_precompile() public view {
        bytes memory data = _mediumInput();
        bytes20 digest = precompileCaller.hash(data);
        assertEq(digest, ripemd160(data));
    }

    function test_ripemd160_medium_pure() public view {
        bytes memory data = _mediumInput();
        bytes20 digest = pureCaller.hash(data);
        assertEq(digest, ripemd160(data));
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
