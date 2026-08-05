// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2 as console} from "forge-std/Test.sol";
import {ModexpMontgomery} from "../../src/modexp/ModexpMontgomery.sol";

contract ProfCaller {
    function modexp(bytes calldata b, bytes calldata e, bytes calldata m)
        external pure returns (bytes memory)
    {
        return ModexpMontgomery.modexp(b, e, m);
    }
}

/// @notice Isolates marginal cost of a squaring / a multiply by diffing
///         exponents with known square-and-multiply counts.
contract ModexpProfileTest is Test {
    ProfCaller c;

    function setUp() public { c = new ProfCaller(); }

    function _g(bytes memory b, bytes memory e, bytes memory m) internal view returns (uint256) {
        uint256 s = gasleft();
        c.modexp(b, e, m);
        return s - gasleft();
    }

    /// exponent = 2^bits -> `bits` squarings, no extra multiplies
    function _pow2(uint256 bits) internal pure returns (bytes memory e) {
        e = new bytes(bits / 8 + 1);
        e[0] = bytes1(uint8(1 << (bits % 8)));
    }

    /// exponent = 2^bits - 1 -> `bits-1` squarings + `bits-1` multiplies
    function _ones(uint256 bits) internal pure returns (bytes memory e) {
        e = new bytes(bits / 8);
        for (uint256 i = 0; i < e.length; i++) e[i] = 0xff;
    }

    /// Deterministic odd modulus of `bytes32Len` bytes with the top bit set.
    function _odd(uint256 len, uint256 seed) internal pure returns (bytes memory v) {
        v = new bytes(len);
        bytes32 h = keccak256(abi.encode(seed));
        for (uint256 i = 0; i < len; i++) {
            if (i % 32 == 0) h = keccak256(abi.encode(h));
            v[i] = h[i % 32];
        }
        v[0] |= 0x80;        // top bit set
        v[len - 1] |= 0x01;  // odd
    }

    function _profile(uint256 bits) internal view {
        uint256 len = bits / 8;
        bytes memory n = _odd(len, 1);
        bytes memory b = _odd(len, 2);

        uint256 g64 = _g(b, _pow2(64), n);
        uint256 g192 = _g(b, _pow2(192), n);
        uint256 sqr = (g192 - g64) / 128;

        uint256 o64 = _g(b, _ones(64), n);
        uint256 o192 = _g(b, _ones(192), n);
        uint256 mul = (o192 - o64) / 128 - sqr;

        // e=1 exits after base reduction: pure call + ABI + limb-conversion cost
        uint256 io = _g(b, hex"01", n);
        // e=2 = full Montgomery setup + 3 montMul (aM, one*r2, final) + 1 montSqr
        uint256 mont = _g(b, hex"02", n) - 3 * mul - sqr - io;
        uint256 e65537 = _g(b, hex"010001", n);

        console.log("--- modulus bits", bits);
        console.log("  k            ", len / 32);
        console.log("  montSqr      ", sqr);
        console.log("  montMul      ", mul);
        console.log("  sqr/mul %    ", (sqr * 100) / mul);
        console.log("  io (e=1)     ", io);
        console.log("  mont setup   ", mont);
        console.log("  e=65537      ", e65537);
        console.log("  setup % of   ", ((io + mont) * 100) / e65537);
    }

    function test_profile_1024() public view { _profile(1024); }
    function test_profile_2048() public view { _profile(2048); }
    function test_profile_3072() public view { _profile(3072); }
    function test_profile_4096() public view { _profile(4096); }

    /// montSqr only beats montMul above some k; find where.
    function test_sqr_vs_mul_crossover() public view {
        for (uint256 k = 4; k <= 16; k++) {
            bytes memory n = _odd(k * 32, 1);
            bytes memory b = _odd(k * 32, 2);
            uint256 sqr = (_g(b, _pow2(192), n) - _g(b, _pow2(64), n)) / 128;
            uint256 mul = (_g(b, _ones(192), n) - _g(b, _ones(64), n)) / 128 - sqr;
            console.log("k", k, "sqr/mul %", (sqr * 100) / mul);
        }
    }
}
