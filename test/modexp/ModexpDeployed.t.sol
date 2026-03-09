// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ModexpDeployed} from "../../src/modexp/ModexpDeployed.sol";

/// @dev Tests that ModexpDeployed is indistinguishable from the 0x05 precompile.
contract ModexpDeployedTest is Test {
    address deployed;

    function setUp() public {
        deployed = address(new ModexpDeployed());
    }

    /// @dev Encode EIP-198 format: [Bsize][Esize][Msize][base][exp][mod]
    function _encodeInput(
        bytes memory base,
        bytes memory exponent,
        bytes memory modulus
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint256(base.length),
            uint256(exponent.length),
            uint256(modulus.length),
            base,
            exponent,
            modulus
        );
    }

    function _callPrecompile(bytes memory input) internal view returns (bool, bytes memory) {
        return address(0x05).staticcall(input);
    }

    function _callDeployed(bytes memory input) internal view returns (bool, bytes memory) {
        return deployed.staticcall(input);
    }

    function test_identical_small() public view {
        // 2^10 mod 7 = 2
        bytes memory input = _encodeInput(
            hex"02",
            hex"0a",
            hex"07"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_rsa2048() public view {
        // RSA-2048 test: base^65537 mod n
        bytes memory base = new bytes(256);
        base[255] = 0x02;
        bytes memory exponent = hex"010001";
        bytes memory modulus = new bytes(256);
        modulus[0] = 0xff;
        modulus[255] = 0xfd;

        bytes memory input = _encodeInput(base, exponent, modulus);
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_zero_base() public view {
        bytes memory input = _encodeInput(
            hex"00",
            hex"05",
            hex"0d"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_exp_one() public view {
        bytes memory input = _encodeInput(
            hex"09",
            hex"01",
            hex"0d"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_even_modulus() public view {
        // 3^7 mod 10
        bytes memory input = _encodeInput(
            hex"03",
            hex"07",
            hex"0a"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_pure_power_of_2() public view {
        // 3^100 mod 256 — modulus is a pure power of 2
        bytes memory input = _encodeInput(
            hex"03",
            hex"64",
            hex"0100"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_even_modulus_large() public view {
        // Large 64-byte even modulus: 2^65537 mod M
        bytes memory base = new bytes(64);
        base[63] = 0x02;
        bytes memory exponent = hex"010001";
        bytes memory modulus = new bytes(64);
        modulus[0] = 0xff;
        modulus[63] = 0xfe; // even

        bytes memory input = _encodeInput(base, exponent, modulus);
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_highly_even_modulus() public view {
        // 7^255 mod (3 * 2^64) — modulus with many trailing zero bits
        bytes memory input = _encodeInput(
            hex"07",
            hex"ff",
            hex"030000000000000000"
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_modulus_power_of_2_single_limb() public view {
        // 0xff^0xffff mod 2^128 — power-of-2 modulus under one 256-bit limb
        bytes memory modulus = new bytes(17);
        modulus[0] = 0x01; // rest are zeros → 2^128

        bytes memory input = _encodeInput(
            hex"ff",
            hex"ffff",
            modulus
        );
        (bool okPre, bytes memory outPre) = _callPrecompile(input);
        (bool okDep, bytes memory outDep) = _callDeployed(input);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }
}
