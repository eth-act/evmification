// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Modexp} from "../../src/modexp/Modexp.sol";
import {ModexpBarrett} from "../../src/modexp/ModexpBarrett.sol";
import {ModexpMontgomery} from "../../src/modexp/ModexpMontgomery.sol";

contract ModexpFuzzRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return Modexp.modexp(base, exponent, modulus);
    }
}

contract BarrettFuzzRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return ModexpBarrett.modexp(base, exponent, modulus);
    }
}

contract MontgomeryFuzzRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return ModexpMontgomery.modexp(base, exponent, modulus);
    }
}

/// @title ModexpFuzzTest
/// @notice Differential fuzz tests for modexp: our implementation vs EVM precompile.
///         Includes both general fuzzing and structured fuzzing biased toward known edge cases.
contract ModexpFuzzTest is Test {
    ModexpFuzzRunner modexpRunner;
    BarrettFuzzRunner barrettRunner;
    MontgomeryFuzzRunner montgomeryRunner;

    function setUp() public {
        modexpRunner = new ModexpFuzzRunner();
        barrettRunner = new BarrettFuzzRunner();
        montgomeryRunner = new MontgomeryFuzzRunner();
    }

    // ── EVM precompile oracle ────────────────────────────────────────────

    function _evmModexp(bytes memory base, bytes memory exp, bytes memory mod_)
        internal view returns (bytes memory)
    {
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exp.length), uint256(mod_.length), base, exp, mod_
        );
        bytes memory result = new bytes(mod_.length);
        assembly {
            let ok := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(result, 0x20), mload(mod_))
            if iszero(ok) { revert(0, 0) }
        }
        return result;
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    function _toMinBytes(uint256 val) internal pure returns (bytes memory) {
        if (val == 0) return hex"00";
        uint256 byteLen;
        uint256 tmp = val;
        while (tmp > 0) { byteLen++; tmp >>= 8; }
        bytes memory result = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            result[byteLen - 1 - i] = bytes1(uint8(val));
            val >>= 8;
        }
        return result;
    }

    /// @dev Pads bytes to exactly `len` bytes (left-pads with zeros).
    function _padTo(bytes memory b, uint256 len) internal pure returns (bytes memory) {
        if (b.length >= len) return b;
        bytes memory result = new bytes(len);
        uint256 offset_ = len - b.length;
        for (uint256 i = 0; i < b.length; i++) {
            result[offset_ + i] = b[i];
        }
        return result;
    }

    /// @dev Create modulus of a specific byte length with controlled properties.
    function _makeModulus(uint256 byteLen, uint256 seed, bool odd) internal pure returns (bytes memory) {
        bytes memory mod_ = new bytes(byteLen);
        // Fill with pseudo-random bytes from seed
        for (uint256 i = 0; i < byteLen; i++) {
            mod_[i] = bytes1(uint8(uint256(keccak256(abi.encodePacked(seed, i)))));
        }
        // Ensure MSB is non-zero (so the modulus actually occupies byteLen bytes)
        if (mod_[0] == 0) mod_[0] = bytes1(uint8(0x01));
        // Ensure odd/even as requested
        uint8 lastByte = uint8(mod_[byteLen - 1]);
        if (odd) {
            mod_[byteLen - 1] = bytes1(lastByte | 0x01);
        } else {
            mod_[byteLen - 1] = bytes1(lastByte & 0xFE);
            // Edge: if all bytes became zero after clearing LSB, set byte 0
            if (uint8(mod_[byteLen - 1]) == 0 && byteLen == 1) {
                mod_[byteLen - 1] = bytes1(uint8(0x02));
            }
        }
        return mod_;
    }

    // ══════════════════════════════════════════════════════════════════════
    // 1. General differential fuzz: random base/exp/mod vs precompile
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_modexp_vs_precompile(
        bytes calldata base,
        bytes calldata exp,
        bytes calldata mod_
    ) public view {
        // Bound to avoid gas explosion: mod <= 128 bytes, exp <= 32 bytes
        // Truncate inputs instead of vm.assume to avoid rejection limit at high run counts
        vm.assume(mod_.length > 0);
        uint256 modLen = mod_.length > 128 ? 128 : mod_.length;
        bytes memory boundedMod = mod_[0:modLen];
        uint256 expLen = exp.length > 32 ? 32 : exp.length;
        bytes memory boundedExp = exp[0:expLen];
        uint256 baseLen = base.length > 128 ? 128 : base.length;
        bytes memory boundedBase = base[0:baseLen];

        bytes memory expected = _evmModexp(boundedBase, boundedExp, boundedMod);
        bytes memory actual = modexpRunner.run(boundedBase, boundedExp, boundedMod);
        assertEq(actual, expected, "general fuzz mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 2. Structured fuzz: odd moduli near limb boundaries (Montgomery)
    // ══════════════════════════════════════════════════════════════════════

    /// @notice Fuzz Montgomery with moduli at specific byte lengths near 32-byte boundaries.
    function testFuzz_montgomery_limb_boundaries(
        uint256 baseSeed,
        uint256 expVal,
        uint8 byteLenChoice,
        uint256 modSeed
    ) public view {
        // Pick modulus byte lengths near limb boundaries: 1,31,32,33,48,63,64,65
        uint256[8] memory byteLens = [uint256(1), 31, 32, 33, 48, 63, 64, 65];
        uint256 byteLen = byteLens[uint256(byteLenChoice) % 8];

        bytes memory mod_ = _makeModulus(byteLen, modSeed, true); // odd
        bytes memory base = _makeModulus(byteLen, baseSeed, false); // any parity
        // Bound exponent to keep gas reasonable
        expVal = bound(expVal, 0, 10000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "montgomery limb boundary mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 3. Structured fuzz: even moduli near limb boundaries (Barrett)
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_barrett_limb_boundaries(
        uint256 baseSeed,
        uint256 expVal,
        uint8 byteLenChoice,
        uint256 modSeed
    ) public view {
        uint256[8] memory byteLens = [uint256(1), 31, 32, 33, 48, 63, 64, 65];
        uint256 byteLen = byteLens[uint256(byteLenChoice) % 8];

        bytes memory mod_ = _makeModulus(byteLen, modSeed, false); // even
        bytes memory base = _makeModulus(byteLen, baseSeed, false);
        expVal = bound(expVal, 0, 10000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "barrett limb boundary mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 4. Structured fuzz: base = modulus - 1 (final subtraction edge)
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_base_eq_mod_minus_1(
        uint256 expVal,
        uint8 byteLenChoice,
        uint256 modSeed
    ) public view {
        uint256[6] memory byteLens = [uint256(1), 31, 32, 33, 48, 64];
        uint256 byteLen = byteLens[uint256(byteLenChoice) % 6];

        bytes memory mod_ = _makeModulus(byteLen, modSeed, true); // odd for Montgomery
        // base = mod - 1: subtract 1 from least significant byte
        bytes memory base = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            base[i] = mod_[i];
        }
        // Subtract 1
        for (uint256 i = byteLen; i > 0;) {
            i--;
            if (uint8(base[i]) > 0) {
                base[i] = bytes1(uint8(base[i]) - 1);
                break;
            }
            base[i] = bytes1(uint8(0xFF));
        }

        expVal = bound(expVal, 1, 1000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "base=mod-1 mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 5. Structured fuzz: small exponents with large moduli
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_small_exp_large_mod(
        uint256 baseSeed,
        uint8 expSmall,
        uint256 modSeed,
        bool oddMod
    ) public view {
        // 64-byte modulus (512-bit), small exponent 0..255
        uint256 byteLen = 64;
        bytes memory mod_ = _makeModulus(byteLen, modSeed, oddMod);
        bytes memory base = _makeModulus(byteLen, baseSeed, false);
        bytes memory exp = _toMinBytes(uint256(expSmall));

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "small exp large mod mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 6. Structured fuzz: base much larger than modulus
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_base_larger_than_mod(
        uint256 baseSeed,
        uint256 expVal,
        uint256 modSeed,
        bool oddMod
    ) public view {
        // 32-byte modulus but 64-byte base (base >> mod)
        bytes memory mod_ = _makeModulus(32, modSeed, oddMod);
        bytes memory base = _makeModulus(64, baseSeed, false);
        expVal = bound(expVal, 1, 5000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "base>mod mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 7. Structured fuzz: power-of-2 moduli (Barrett with trailing zeros)
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_power_of_2_modulus(
        uint256 baseSeed,
        uint256 expVal,
        uint8 powerChoice
    ) public view {
        // Powers: 2^8, 2^16, 2^32, 2^64, 2^128, 2^256
        uint256[6] memory powers = [uint256(8), 16, 32, 64, 128, 256];
        uint256 power = powers[uint256(powerChoice) % 6];
        uint256 modByteLen = power / 8 + 1;

        bytes memory mod_ = new bytes(modByteLen);
        mod_[0] = 0x01; // 2^power = 0x01 followed by zeros

        bytes memory base = _makeModulus(modByteLen, baseSeed, false);
        expVal = bound(expVal, 0, 5000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "power-of-2 mod mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 8. Structured fuzz: moduli near 2^(256k) (Barrett constant edges)
    // ══════════════════════════════════════════════════════════════════════

    function testFuzz_mod_near_limb_power(
        uint256 baseSeed,
        uint256 expVal,
        uint8 sizeChoice,
        uint8 offset_
    ) public view {
        // Modulus = (2^N - offset) where N is a limb boundary, offset is small
        uint256[3] memory sizes = [uint256(256), 512, 1024];
        uint256 n = sizes[uint256(sizeChoice) % 3];
        uint256 byteLen = n / 8;
        uint256 off = bound(uint256(offset_), 1, 200);

        // Build 2^n - off: start with all 0xFF, subtract (off - 1)
        bytes memory mod_ = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            mod_[i] = 0xFF;
        }
        uint256 sub_ = off - 1;
        for (uint256 i = byteLen; i > 0 && sub_ > 0;) {
            i--;
            uint256 cur = uint8(mod_[i]);
            uint256 digit = sub_ & 0xFF;
            if (cur >= digit) {
                mod_[i] = bytes1(uint8(cur - digit));
                sub_ >>= 8;
            } else {
                mod_[i] = bytes1(uint8(256 + cur - digit));
                sub_ = (sub_ >> 8) + 1;
            }
        }

        bytes memory base = _makeModulus(byteLen, baseSeed, false);
        expVal = bound(expVal, 1, 2000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = modexpRunner.run(base, exp, mod_);
        assertEq(actual, expected, "near-limb-power mod mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 9. Barrett bounds stress: moduli with tiny top limb (maximizes mu)
    // ══════════════════════════════════════════════════════════════════════

    /// @notice When the modulus top limb is tiny (e.g., 0x01), the Barrett
    ///         constant mu ≈ 2^{256(k+1)} is maximal. This maximizes q3
    ///         (the quotient estimate), stressing the truncated-multiply
    ///         loop bounds in _barrettMulMod Step 6.
    function testFuzz_barrett_tiny_top_limb(
        uint256 baseSeed,
        uint256 expVal,
        uint8 sizeChoice,
        uint256 modSeed
    ) public view {
        // Multi-limb even moduli: 33 bytes (2 limbs), 34 bytes (2 limbs), 65 bytes (3 limbs)
        uint256[3] memory byteLens = [uint256(33), 34, 65];
        uint256 byteLen = byteLens[uint256(sizeChoice) % 3];

        // Build modulus with a tiny first byte (0x01) to minimize the top limb
        bytes memory mod_ = new bytes(byteLen);
        mod_[0] = 0x01;
        for (uint256 i = 1; i < byteLen; i++) {
            mod_[i] = bytes1(uint8(uint256(keccak256(abi.encodePacked(modSeed, i)))));
        }
        // Force even (Barrett path)
        mod_[byteLen - 1] = bytes1(uint8(mod_[byteLen - 1]) & 0xFE);
        if (uint8(mod_[byteLen - 1]) == 0) mod_[byteLen - 1] = bytes1(uint8(0x02));

        // Base nearly as large as mod (maximizes the product a*b in Barrett)
        bytes memory base = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            base[i] = mod_[i]; // start equal to mod
        }
        // Subtract a small random amount so base < mod
        base[byteLen - 1] = bytes1(uint8(uint256(keccak256(abi.encodePacked(baseSeed))) % 256));

        expVal = bound(expVal, 2, 5000);
        bytes memory exp = _toMinBytes(expVal);

        bytes memory expected = _evmModexp(base, exp, mod_);
        bytes memory actual = barrettRunner.run(base, exp, mod_);
        assertEq(actual, expected, "barrett tiny top limb mismatch");
    }

    // ══════════════════════════════════════════════════════════════════════
    // 10. Structured fuzz: dispatcher consistency (same inputs, both paths)
    // ══════════════════════════════════════════════════════════════════════

    /// @notice Same base/exp but test with modulus and modulus+1 to hit both paths.
    function testFuzz_dispatcher_odd_even(
        uint256 baseSeed,
        uint256 expVal,
        uint256 modSeed,
        uint8 byteLenChoice
    ) public view {
        uint256[4] memory byteLens = [uint256(1), 32, 33, 64];
        uint256 byteLen = byteLens[uint256(byteLenChoice) % 4];

        // Make an even modulus
        bytes memory evenMod = _makeModulus(byteLen, modSeed, false);
        // Make the same modulus but odd (set LSB)
        bytes memory oddMod = new bytes(byteLen);
        for (uint256 i = 0; i < byteLen; i++) {
            oddMod[i] = evenMod[i];
        }
        oddMod[byteLen - 1] = bytes1(uint8(oddMod[byteLen - 1]) | 0x01);

        bytes memory base = _makeModulus(byteLen, baseSeed, false);
        expVal = bound(expVal, 1, 5000);
        bytes memory exp = _toMinBytes(expVal);

        // Both should match precompile
        bytes memory expectedEven = _evmModexp(base, exp, evenMod);
        bytes memory actualEven = modexpRunner.run(base, exp, evenMod);
        assertEq(actualEven, expectedEven, "dispatcher even mismatch");

        bytes memory expectedOdd = _evmModexp(base, exp, oddMod);
        bytes memory actualOdd = modexpRunner.run(base, exp, oddMod);
        assertEq(actualOdd, expectedOdd, "dispatcher odd mismatch");
    }
}
