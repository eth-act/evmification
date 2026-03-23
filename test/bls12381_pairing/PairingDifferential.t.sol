// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Pairing} from "../../src/bls12381_pairing/Pairing.sol";
import {PairingPrecompile} from "../../src/bls12381_pairing/PairingPrecompile.sol";

contract PairingCaller {
    function pairing(bytes calldata input) external pure returns (bytes memory) {
        return Pairing.pairing(input);
    }
}

contract PairingDifferentialTest is Test {
    PairingCaller caller;

    // BLS12-381 G1 generator
    bytes constant G1_X = hex"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant G1_Y = hex"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    // BLS12-381 G2 generator
    bytes constant G2_X_C0 = hex"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    bytes constant G2_X_C1 = hex"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant G2_Y_C0 = hex"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
    bytes constant G2_Y_C1 = hex"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    // Negated G1 generator (y = p - G1_Y)
    bytes constant NEG_G1_Y = hex"114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    function setUp() public {
        caller = new PairingCaller();
    }

    /// @dev Encode a G1 point as 128 bytes in EIP-2537 format.
    function _encodeG1(bytes memory x, bytes memory y) private pure returns (bytes memory result) {
        result = new bytes(128);
        assembly {
            let dst := add(result, 0x20)
            mstore(add(dst, 16), mload(add(x, 0x20)))
            mstore(add(dst, 32), mload(add(x, 0x30)))
            mstore(add(dst, 80), mload(add(y, 0x20)))
            mstore(add(dst, 96), mload(add(y, 0x30)))
        }
    }

    /// @dev Encode a G2 point as 256 bytes in EIP-2537 format.
    function _encodeG2(
        bytes memory xc0,
        bytes memory xc1,
        bytes memory yc0,
        bytes memory yc1
    ) private pure returns (bytes memory result) {
        result = new bytes(256);
        _writeFp(result, 0, xc0);
        _writeFp(result, 64, xc1);
        _writeFp(result, 128, yc0);
        _writeFp(result, 192, yc1);
    }

    /// @dev Write a 48-byte Fp element into a 64-byte block in output.
    function _writeFp(bytes memory output, uint256 blockOffset, bytes memory fp) private pure {
        assembly {
            let dst := add(add(output, 0x20), blockOffset)
            let src := add(fp, 0x20)
            mstore(add(dst, 16), mload(src))
            let tail := shl(128, shr(128, mload(add(src, 32))))
            let existing := and(mload(add(dst, 48)), 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            mstore(add(dst, 48), or(tail, existing))
        }
    }

    /// @dev Build a pairing input from one (G1, G2) pair.
    function _buildPair(bytes memory g1, bytes memory g2) private pure returns (bytes memory result) {
        result = new bytes(384);
        assembly {
            let dst := add(result, 0x20)
            let src1 := add(g1, 0x20)
            // Copy G1 (128 bytes = 4 words)
            mstore(dst, mload(src1))
            mstore(add(dst, 32), mload(add(src1, 32)))
            mstore(add(dst, 64), mload(add(src1, 64)))
            mstore(add(dst, 96), mload(add(src1, 96)))
            // Copy G2 (256 bytes = 8 words)
            let src2 := add(g2, 0x20)
            mstore(add(dst, 128), mload(src2))
            mstore(add(dst, 160), mload(add(src2, 32)))
            mstore(add(dst, 192), mload(add(src2, 64)))
            mstore(add(dst, 224), mload(add(src2, 96)))
            mstore(add(dst, 256), mload(add(src2, 128)))
            mstore(add(dst, 288), mload(add(src2, 160)))
            mstore(add(dst, 320), mload(add(src2, 192)))
            mstore(add(dst, 352), mload(add(src2, 224)))
        }
    }

    /// @dev Concatenate two 384-byte pair inputs into 768 bytes.
    function _concat(bytes memory a, bytes memory b) private pure returns (bytes memory result) {
        result = new bytes(a.length + b.length);
        assembly {
            let dst := add(result, 0x20)
            let srcA := add(a, 0x20)
            let lenA := mload(a)
            // Copy a
            for { let i := 0 } lt(i, lenA) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(srcA, i)))
            }
            // Copy b
            let srcB := add(b, 0x20)
            let lenB := mload(b)
            for { let i := 0 } lt(i, lenB) { i := add(i, 32) } {
                mstore(add(add(dst, lenA), i), mload(add(srcB, i)))
            }
        }
    }

    function _g1Gen() private pure returns (bytes memory) {
        return _encodeG1(G1_X, G1_Y);
    }

    function _negG1Gen() private pure returns (bytes memory) {
        return _encodeG1(G1_X, NEG_G1_Y);
    }

    function _g2Gen() private pure returns (bytes memory) {
        return _encodeG2(G2_X_C0, G2_X_C1, G2_Y_C0, G2_Y_C1);
    }

    // ── Tests ────────────────────────────────────────────────────────────

    /// @dev Empty input: product of zero pairings = 1, should return 0x..01.
    function test_empty_input() public view {
        bytes memory input = new bytes(0);
        // Note: the native precompile may error on empty input.
        // Our implementation should return 1 (product of zero pairings).
        bytes memory actual = caller.pairing(input);
        assertEq(uint8(actual[31]), 1, "empty input should give 1");
    }

    /// @dev e(G1, G2) * e(-G1, G2) = 1 (should return 0x..01).
    function test_pairing_negation() public view {
        bytes memory pair1 = _buildPair(_g1Gen(), _g2Gen());
        bytes memory pair2 = _buildPair(_negG1Gen(), _g2Gen());
        bytes memory input = _concat(pair1, pair2);

        bytes memory expected = PairingPrecompile.pairing(input);
        bytes memory actual = caller.pairing(input);
        assertEq(actual, expected, "negation pairing mismatch");
        // Should be 1
        assertEq(uint8(actual[31]), 1, "negation should give 1");
    }

    /// @dev e(G1, G2) alone should not be 1 (should return 0x..00).
    function test_single_pairing_not_one() public view {
        bytes memory input = _buildPair(_g1Gen(), _g2Gen());

        bytes memory expected = PairingPrecompile.pairing(input);
        bytes memory actual = caller.pairing(input);
        assertEq(actual, expected, "single pairing mismatch");
        assertEq(uint8(actual[31]), 0, "single pairing should not be 1");
    }

    /// @dev Infinity points: e(O, G2) should contribute 1 to the product.
    function test_infinity_g1() public view {
        bytes memory infG1 = new bytes(128);
        bytes memory input = _buildPair(infG1, _g2Gen());

        bytes memory expected = PairingPrecompile.pairing(input);
        bytes memory actual = caller.pairing(input);
        assertEq(actual, expected, "infinity G1 mismatch");
        // Single pair with infinity = product is 1 (only term is identity)
        assertEq(uint8(actual[31]), 1, "infinity G1 should give 1");
    }

    /// @dev Infinity G2: e(G1, O) should contribute 1.
    function test_infinity_g2() public view {
        bytes memory infG2 = new bytes(256);
        bytes memory input = _buildPair(_g1Gen(), infG2);

        bytes memory expected = PairingPrecompile.pairing(input);
        bytes memory actual = caller.pairing(input);
        assertEq(actual, expected, "infinity G2 mismatch");
        assertEq(uint8(actual[31]), 1, "infinity G2 should give 1");
    }

    /// @dev Two pairs of (G1, G2) — product is e(G1,G2)^2, should NOT be 1.
    function test_two_same_pairs() public view {
        bytes memory pair = _buildPair(_g1Gen(), _g2Gen());
        bytes memory input = _concat(pair, pair);

        bytes memory expected = PairingPrecompile.pairing(input);
        bytes memory actual = caller.pairing(input);
        assertEq(actual, expected, "two same pairs mismatch");
    }
}
