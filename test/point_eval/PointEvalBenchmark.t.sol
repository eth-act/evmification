// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {PointEvalPrecompile} from "../../src/point_eval/PointEvalPrecompile.sol";
import {PointEval} from "../../src/point_eval/PointEval.sol";

/// @notice Thin wrapper to make precompile library calls external for gas measurement.
contract PointEvalPrecompileCaller {
    function verify(bytes calldata input) external view returns (uint256, uint256) {
        return PointEvalPrecompile.verify(input);
    }
}

/// @notice Thin wrapper to make BLS library calls external for gas measurement.
contract PointEvalBLSCaller {
    function verify(bytes calldata input) external view returns (uint256, uint256) {
        return PointEval.verify(input);
    }
}

contract PointEvalBenchmarkTest is Test {
    PointEvalPrecompileCaller precompileCaller;
    PointEvalBLSCaller blsCaller;

    // Test vector 2: linear polynomial f(x)=x, z=7, y=7
    bytes constant VALID_INPUT =
        hex"014fa3bb4018340ca2fa8eb239e23af6ba465f6d5bc31db78988445da078db76"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"ad3eb50121139aa34db1d545093ac9374ab7bca2c0f3bf28e27c8dcd8fc7cb42d25926fc0c97b336e9f0fb35e5a04c81"
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    function setUp() public {
        precompileCaller = new PointEvalPrecompileCaller();
        blsCaller = new PointEvalBLSCaller();
    }

    function test_benchmark_precompile() public view {
        (uint256 fe, uint256 mod) = precompileCaller.verify(VALID_INPUT);
        assertEq(fe, 4096);
        assertEq(mod, 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001);
    }

    function test_benchmark_bls() public view {
        (uint256 fe, uint256 mod) = blsCaller.verify(VALID_INPUT);
        assertEq(fe, 4096);
        assertEq(mod, 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001);
    }
}
