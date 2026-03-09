// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ModexpPow2} from "../../src/modexp/ModexpPow2.sol";
import {ModexpPrecompile} from "../../src/modexp/ModexpPrecompile.sol";

/// @dev Wrapper that calls the pure ModexpPow2 library.
contract ModexpPow2Caller {
    function modexp(bytes calldata base, bytes calldata exponent, uint256 kBits)
        external pure returns (bytes memory)
    {
        return ModexpPow2.modexp(base, exponent, kBits);
    }
}

/// @dev Wrapper that calls the 0x05 precompile via ModexpPrecompile.
contract PrecompilePow2Caller {
    /// @notice Computes base^exp mod 2^kBits via the native precompile.
    /// @dev The modulus 2^kBits occupies ceil((kBits+1)/8) bytes.
    ///      The precompile returns bytes of that length, but our library
    ///      returns ceil(kBits/8) bytes. We trim the leading byte from
    ///      the precompile result so the two are comparable.
    function modexp(bytes calldata base, bytes calldata exponent, uint256 kBits)
        external view returns (bytes memory)
    {
        bytes memory mod = _pow2Modulus(kBits);
        bytes memory raw = ModexpPrecompile.modexp(base, exponent, mod);
        // raw.length == mod.length == ceil((kBits+1)/8)
        // We want ceil(kBits/8) bytes, so strip the leading byte.
        uint256 wantLen = (kBits + 7) / 8;
        if (raw.length > wantLen) {
            bytes memory trimmed = new bytes(wantLen);
            // Copy the trailing wantLen bytes from raw.
            uint256 offset = raw.length - wantLen;
            for (uint256 i = 0; i < wantLen; i++) {
                trimmed[i] = raw[offset + i];
            }
            return trimmed;
        }
        return raw;
    }

    /// @dev Builds the big-endian representation of 2^kBits.
    ///      Needs ceil((kBits+1)/8) bytes. The high byte has a single bit set.
    function _pow2Modulus(uint256 kBits) internal pure returns (bytes memory mod) {
        uint256 byteLen = (kBits + 8) / 8; // == ceil((kBits+1)/8)
        mod = new bytes(byteLen);
        // Bit position within the byte array (big-endian):
        //   byte index 0 is the most significant byte.
        //   2^kBits means bit kBits is set.
        //   In a byteLen-byte big-endian number, bit kBits is at:
        //     byte index = byteLen - 1 - (kBits / 8)
        //     bit  index = kBits % 8
        uint256 byteIdx = byteLen - 1 - (kBits / 8);
        uint256 bitIdx = kBits % 8;
        mod[byteIdx] = bytes1(uint8(1 << bitIdx));
    }
}

contract ModexpPow2Test is Test {
    ModexpPow2Caller pow2;
    PrecompilePow2Caller precompile;

    function setUp() public {
        pow2 = new ModexpPow2Caller();
        precompile = new PrecompilePow2Caller();
    }

    // ── Small deterministic tests ────────────────────────────────────

    /// @dev 3^7 mod 2^3 = 2187 mod 8 = 3
    function test_small_3pow7_mod8() public {
        bytes memory base = hex"03";
        bytes memory exp = hex"07";
        uint256 kBits = 3;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        // Sanity: 2187 mod 8 = 3 => expected == 0x03 (1 byte)
        assertEq(expected.length, 1);
        assertEq(uint8(expected[0]), 3);

        // Library (stub will revert; once implemented it must match)
        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "3^7 mod 8 mismatch");
    }

    /// @dev 2^10 mod 2^4 = 1024 mod 16 = 0
    function test_small_2pow10_mod16() public {
        bytes memory base = hex"02";
        bytes memory exp = hex"0a";
        uint256 kBits = 4;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        assertEq(expected.length, 1);
        assertEq(uint8(expected[0]), 0);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "2^10 mod 16 mismatch");
    }

    /// @dev 3^0xffff mod 2^256, compared against precompile
    function test_single_limb_mod2pow256() public {
        bytes memory base = hex"03";
        bytes memory exp = hex"ffff";
        uint256 kBits = 256;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        assertEq(expected.length, 32);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "3^0xffff mod 2^256 mismatch");
    }

    /// @dev 0xff^0xffff mod 2^512, compared against precompile
    function test_multi_limb_mod2pow512() public {
        bytes memory base = hex"ff";
        bytes memory exp = hex"ffff";
        uint256 kBits = 512;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        assertEq(expected.length, 64);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "0xff^0xffff mod 2^512 mismatch");
    }

    /// @dev x^0 mod 2^k = 1 (for any non-zero modulus)
    function test_zero_exponent() public {
        bytes memory base = hex"07";
        bytes memory exp = hex"00";
        uint256 kBits = 256;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        // Should be 1, left-padded to 32 bytes
        assertEq(expected.length, 32);
        assertEq(uint8(expected[31]), 1);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "x^0 mod 2^256 mismatch");
    }

    /// @dev 0^5 mod 2^k = 0
    function test_zero_base() public {
        bytes memory base = hex"00";
        bytes memory exp = hex"05";
        uint256 kBits = 256;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        assertEq(expected.length, 32);
        assertEq(uint8(expected[31]), 0);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "0^5 mod 2^256 mismatch");
    }

    /// @dev 3^7 mod 2^1 = 2187 mod 2 = 1
    function test_kBits_1() public {
        bytes memory base = hex"03";
        bytes memory exp = hex"07";
        uint256 kBits = 1;

        bytes memory expected = precompile.modexp(base, exp, kBits);
        assertEq(expected.length, 1);
        assertEq(uint8(expected[0]), 1);

        bytes memory actual = pow2.modexp(base, exp, kBits);
        assertEq(actual, expected, "3^7 mod 2 mismatch");
    }
}
