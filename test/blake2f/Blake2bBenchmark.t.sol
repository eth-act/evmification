// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2b} from "../../examples/blake2f/Blake2b.sol";
import {Blake2bPure} from "../../examples/blake2f/Blake2bPure.sol";

/// @notice Thin wrapper to make precompile library calls external for gas measurement.
contract Blake2bCaller {
    function hash(bytes calldata data, uint64 outlen) external view returns (bytes memory) {
        return Blake2b.hash(data, outlen);
    }
}

/// @notice Thin wrapper to make pure library calls external for gas measurement.
contract Blake2bPureCaller {
    function hash(bytes calldata data, uint64 outlen) external pure returns (bytes memory) {
        return Blake2bPure.hash(data, outlen);
    }
}

contract Blake2bBenchmarkTest is Test {
    Blake2bCaller precompileCaller;
    Blake2bPureCaller pureCaller;

    bytes constant SHORT_INPUT = hex"68656c6c6f"; // "hello"

    function setUp() public {
        precompileCaller = new Blake2bCaller();
        pureCaller = new Blake2bPureCaller();
    }

    // ── Short input (single block) ─────────────────────────────

    function test_blake2b256_short_precompile() public view {
        bytes memory digest = precompileCaller.hash(SHORT_INPUT, 32);
        assertEq(digest, hex"324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf");
    }

    function test_blake2b256_short_pure() public view {
        bytes memory digest = pureCaller.hash(SHORT_INPUT, 32);
        assertEq(digest, hex"324dcf027dd4a30a932c441f365a25e86b173defa4b8e58948253471b81b72cf");
    }

    // ── 32-byte input (single block) ─────────────────────────────

    function test_blake2b256_32bytes_precompile() public view {
        bytes memory data = _32byteInput();
        bytes memory digest = precompileCaller.hash(data, 32);
        assertEq(digest, hex"cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6");
    }

    function test_blake2b256_32bytes_pure() public view {
        bytes memory data = _32byteInput();
        bytes memory digest = pureCaller.hash(data, 32);
        assertEq(digest, hex"cb2f5160fc1f7e05a55ef49d340b48da2e5a78099d53393351cd579dd42503d6");
    }

    // ── Medium input (~256 bytes, multi-block) ─────────────────

    function test_blake2b256_medium_precompile() public view {
        bytes memory data = _mediumInput();
        bytes memory digest = precompileCaller.hash(data, 32);
        assertEq(digest, hex"50fd807b5e2b4bc2c3fe7194c9c81292fc83412874814f1b93df31ada4f0f876");
    }

    function test_blake2b256_medium_pure() public view {
        bytes memory data = _mediumInput();
        bytes memory digest = pureCaller.hash(data, 32);
        assertEq(digest, hex"50fd807b5e2b4bc2c3fe7194c9c81292fc83412874814f1b93df31ada4f0f876");
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
            // Fill 256 bytes with 0x42 (8 words of 0x4242...42)
            let word := 0x4242424242424242424242424242424242424242424242424242424242424242
            for { let i := 0 } lt(i, 256) { i := add(i, 32) } {
                mstore(add(ptr, i), word)
            }
        }
    }
}
