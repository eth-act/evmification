// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {G2Add} from "../../src/bls12381_g2add/G2Add.sol";
import {G2AddPrecompile} from "../../src/bls12381_g2add/G2AddPrecompile.sol";
import {Fp} from "../../src/bls12381/Fp.sol";
import {Fp2} from "../../src/bls12381/Fp2.sol";

contract G2AddCaller {
    function g2Add(bytes calldata input) external pure returns (bytes memory) {
        return G2Add.g2Add(input);
    }
}

contract G2AddDifferentialTest is Test {
    G2AddCaller caller;

    // BLS12-381 base field modulus
    bytes constant P =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    function setUp() public {
        caller = new G2AddCaller();
    }

    /// @dev Map an Fp2 element to a G2 point using the native MAP_FP_TO_G2 precompile (0x11).
    function _mapToG2(uint256 c0, uint256 c1) private view returns (bytes memory) {
        bytes memory input = new bytes(128);
        assembly {
            let ptr := add(input, 0x20)
            mstore(add(ptr, 0x20), c0)
            mstore(add(ptr, 0x60), c1)
        }
        bytes memory output = new bytes(256);
        assembly {
            let ok := staticcall(gas(), 0x11, add(input, 0x20), 128, add(output, 0x20), 256)
            if iszero(ok) { revert(0, 0) }
        }
        return output;
    }

    /// @dev Negate a G2 point by negating y (both c0 and c1 via Fp.neg).
    function _negateG2(bytes memory point) private pure returns (bytes memory result) {
        result = new bytes(256);
        // Copy x (first 128 bytes) as-is
        assembly {
            let src := add(point, 0x20)
            let dst := add(result, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
            mstore(add(dst, 0x40), mload(add(src, 0x40)))
            mstore(add(dst, 0x60), mload(add(src, 0x60)))
        }
        // Extract y.c0 at offset 128 and y.c1 at offset 192
        bytes memory yc0 = _extractFp(point, 128);
        bytes memory yc1 = _extractFp(point, 192);
        // Negate
        bytes memory nyc0 = Fp.neg(yc0);
        bytes memory nyc1 = Fp.neg(yc1);
        // Write back
        _writeFp(result, 128, nyc0);
        _writeFp(result, 192, nyc1);
    }

    /// @dev Extract a 48-byte Fp element from a 64-byte padded block at offset.
    function _extractFp(bytes memory data, uint256 offset) private pure returns (bytes memory fp) {
        fp = new bytes(48);
        assembly {
            let src := add(add(data, 0x20), add(offset, 16))
            let dst := add(fp, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 16), mload(add(src, 16)))
        }
    }

    /// @dev Write a 48-byte Fp element into a 64-byte padded block at offset.
    function _writeFp(bytes memory data, uint256 offset, bytes memory fp) private pure {
        assembly {
            let src := add(fp, 0x20)
            let dst := add(add(data, 0x20), add(offset, 16))
            mstore(dst, mload(src))
            // Write last 16 bytes carefully to avoid overflow
            let tail := shl(128, shr(128, mload(add(src, 32))))
            let existing := and(mload(add(dst, 32)), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(dst, 32), or(tail, existing))
        }
    }

    /// @dev Call the native G2ADD precompile (0x0d) for comparison.
    function _nativeG2Add(bytes memory input) private view returns (bytes memory output) {
        return G2AddPrecompile.g2Add(input);
    }

    /// @dev Concatenate two 256-byte G2 points into a 512-byte input.
    function _concat(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        result = new bytes(512);
        assembly {
            let dst := add(result, 0x20)
            let srcA := add(a, 0x20)
            let srcB := add(b, 0x20)
            // Copy 256 bytes from a
            mstore(dst, mload(srcA))
            mstore(add(dst, 0x20), mload(add(srcA, 0x20)))
            mstore(add(dst, 0x40), mload(add(srcA, 0x40)))
            mstore(add(dst, 0x60), mload(add(srcA, 0x60)))
            mstore(add(dst, 0x80), mload(add(srcA, 0x80)))
            mstore(add(dst, 0xa0), mload(add(srcA, 0xa0)))
            mstore(add(dst, 0xc0), mload(add(srcA, 0xc0)))
            mstore(add(dst, 0xe0), mload(add(srcA, 0xe0)))
            // Copy 256 bytes from b
            mstore(add(dst, 0x100), mload(srcB))
            mstore(add(dst, 0x120), mload(add(srcB, 0x20)))
            mstore(add(dst, 0x140), mload(add(srcB, 0x40)))
            mstore(add(dst, 0x160), mload(add(srcB, 0x60)))
            mstore(add(dst, 0x180), mload(add(srcB, 0x80)))
            mstore(add(dst, 0x1a0), mload(add(srcB, 0xa0)))
            mstore(add(dst, 0x1c0), mload(add(srcB, 0xc0)))
            mstore(add(dst, 0x1e0), mload(add(srcB, 0xe0)))
        }
    }

    function test_g2add_p_plus_q() public view {
        bytes memory P1 = _mapToG2(1, 2);
        bytes memory P2 = _mapToG2(3, 4);
        bytes memory input = _concat(P1, P2);

        bytes memory expected = _nativeG2Add(input);
        bytes memory actual = caller.g2Add(input);
        assertEq(actual, expected, "P+Q mismatch");
    }

    function test_g2add_p_plus_identity() public view {
        bytes memory P1 = _mapToG2(5, 6);
        bytes memory O = new bytes(256);
        bytes memory input = _concat(P1, O);

        bytes memory expected = _nativeG2Add(input);
        bytes memory actual = caller.g2Add(input);
        assertEq(actual, expected, "P+O mismatch");
    }

    function test_g2add_identity_plus_identity() public view {
        bytes memory O = new bytes(256);
        bytes memory input = _concat(O, O);

        bytes memory expected = _nativeG2Add(input);
        bytes memory actual = caller.g2Add(input);
        assertEq(actual, expected, "O+O mismatch");
    }

    function test_g2add_doubling() public view {
        bytes memory P1 = _mapToG2(7, 8);
        bytes memory input = _concat(P1, P1);

        bytes memory expected = _nativeG2Add(input);
        bytes memory actual = caller.g2Add(input);
        assertEq(actual, expected, "P+P mismatch");
    }

    function test_g2add_p_plus_neg_p() public view {
        bytes memory P1 = _mapToG2(9, 10);
        bytes memory negP1 = _negateG2(P1);
        bytes memory input = _concat(P1, negP1);

        bytes memory expected = _nativeG2Add(input);
        bytes memory actual = caller.g2Add(input);
        assertEq(actual, expected, "P+(-P) mismatch");
    }
}
