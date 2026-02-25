// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IdentityPrecompile} from "../../src/identity/IdentityPrecompile.sol";
import {Identity} from "../../src/identity/Identity.sol";

/// @notice Thin wrapper to make precompile library calls external for gas measurement.
contract IdentityPrecompileCaller {
    function identity(bytes calldata data) external view returns (bytes memory) {
        return IdentityPrecompile.identity(data);
    }
}

/// @notice Thin wrapper to make pure library calls external for gas measurement.
contract IdentityPureCaller {
    function identity(bytes calldata data) external pure returns (bytes memory) {
        return Identity.identity(data);
    }
}

contract IdentityBenchmarkTest is Test {
    IdentityPrecompileCaller precompileCaller;
    IdentityPureCaller pureCaller;

    bytes constant SHORT_INPUT = hex"68656c6c6f"; // "hello"

    function setUp() public {
        precompileCaller = new IdentityPrecompileCaller();
        pureCaller = new IdentityPureCaller();
    }

    // ── Short input (5 bytes) ───────────────────────────────────

    function test_identity_short_precompile() public view {
        bytes memory result = precompileCaller.identity(SHORT_INPUT);
        assertEq(result, SHORT_INPUT);
    }

    function test_identity_short_pure() public view {
        bytes memory result = pureCaller.identity(SHORT_INPUT);
        assertEq(result, SHORT_INPUT);
    }

    // ── 32-byte input ───────────────────────────────────────────

    function test_identity_32bytes_precompile() public view {
        bytes memory result = precompileCaller.identity(_32byteInput());
        assertEq(keccak256(result), keccak256(_32byteInput()));
    }

    function test_identity_32bytes_pure() public view {
        bytes memory result = pureCaller.identity(_32byteInput());
        assertEq(keccak256(result), keccak256(_32byteInput()));
    }

    // ── Medium input (~256 bytes) ───────────────────────────────

    function test_identity_medium_precompile() public view {
        bytes memory result = precompileCaller.identity(_mediumInput());
        assertEq(keccak256(result), keccak256(_mediumInput()));
    }

    function test_identity_medium_pure() public view {
        bytes memory result = pureCaller.identity(_mediumInput());
        assertEq(keccak256(result), keccak256(_mediumInput()));
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
