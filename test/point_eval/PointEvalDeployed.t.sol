// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {PointEvalDeployed} from "../../src/point_eval/PointEvalDeployed.sol";

/// @dev Tests that PointEvalDeployed is indistinguishable from the 0x0a precompile.
contract PointEvalDeployedTest is Test {
    address deployed;

    function setUp() public {
        deployed = address(new PointEvalDeployed());
    }

    function _callPrecompile(bytes memory input) internal view returns (bool, bytes memory) {
        return address(0x0a).staticcall(input);
    }

    function _callDeployed(bytes memory input) internal view returns (bool, bytes memory) {
        return deployed.staticcall(input);
    }

    // Test vector 1: constant polynomial f(x)=1
    bytes constant VALID_INPUT_1 =
        hex"01cf478a431837728dcec3461f4f53b8749cdc4e03496dcaed459dea82b82eb8"
        hex"0000000000000000000000000000000000000000000000000000000000000001"
        hex"0000000000000000000000000000000000000000000000000000000000000001"
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    // Test vector 2: linear polynomial f(x)=x
    bytes constant VALID_INPUT_2 =
        hex"014fa3bb4018340ca2fa8eb239e23af6ba465f6d5bc31db78988445da078db76"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"ad3eb50121139aa34db1d545093ac9374ab7bca2c0f3bf28e27c8dcd8fc7cb42d25926fc0c97b336e9f0fb35e5a04c81"
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    function test_identical_vector1() public view {
        (bool okPre, bytes memory outPre) = _callPrecompile(VALID_INPUT_1);
        (bool okDep, bytes memory outDep) = _callDeployed(VALID_INPUT_1);
        assertTrue(okPre, "precompile failed");
        assertTrue(okDep, "deployed failed");
        assertEq(outDep, outPre);
    }

    function test_identical_vector2() public view {
        (bool okPre, bytes memory outPre) = _callPrecompile(VALID_INPUT_2);
        (bool okDep, bytes memory outDep) = _callDeployed(VALID_INPUT_2);
        assertTrue(okPre, "precompile failed");
        assertTrue(okDep, "deployed failed");
        assertEq(outDep, outPre);
    }
}
