// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2fPrecompile} from "../../src/blake2f/Blake2fPrecompile.sol";
import {Blake2f} from "../../src/blake2f/Blake2f.sol";

contract Blake2fPrecompileCaller {
    function compress(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) external view returns (uint64[8] memory) {
        return Blake2fPrecompile.compress(rounds, h, m, t, finalBlock);
    }
}

contract Blake2fPureCaller {
    function compress(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) external pure returns (uint64[8] memory) {
        return Blake2f.compress(rounds, h, m, t, finalBlock);
    }
}

contract Blake2fDifferentialTest is Test {
    Blake2fPrecompileCaller precompile;
    Blake2fPureCaller pure_;

    function setUp() public {
        precompile = new Blake2fPrecompileCaller();
        pure_ = new Blake2fPureCaller();
    }

    function test_zero_rounds() public view {
        uint64[8] memory h;
        uint64[16] memory m;
        uint64[2] memory t;
        uint64[8] memory expected = precompile.compress(0, h, m, t, true);
        uint64[8] memory actual = pure_.compress(0, h, m, t, true);
        _assertEq8(actual, expected, "zero rounds");
    }

    function test_one_round_final() public view {
        uint64[8] memory h;
        h[0] = 0x6a09e667f2bdc948;
        h[1] = 0xbb67ae8584caa73b;
        h[2] = 0x3c6ef372fe94f82b;
        h[3] = 0xa54ff53a5f1d36f1;
        h[4] = 0x510e527fade682d1;
        h[5] = 0x9b05688c2b3e6c1f;
        h[6] = 0x1f83d9abfb41bd6b;
        h[7] = 0x5be0cd19137e2179;
        uint64[16] memory m;
        m[0] = 0x0000000000636261;
        uint64[2] memory t;
        t[0] = 3;

        uint64[8] memory expected = precompile.compress(1, h, m, t, true);
        uint64[8] memory actual = pure_.compress(1, h, m, t, true);
        _assertEq8(actual, expected, "one round final");
    }

    function test_one_round_not_final() public view {
        uint64[8] memory h;
        h[0] = 0x6a09e667f2bdc948;
        uint64[16] memory m;
        m[0] = 0x0000000000636261;
        uint64[2] memory t;
        t[0] = 3;

        uint64[8] memory expected = precompile.compress(1, h, m, t, false);
        uint64[8] memory actual = pure_.compress(1, h, m, t, false);
        _assertEq8(actual, expected, "one round not final");
    }

    function testFuzz_pure_matches_precompile(
        uint32 rounds,
        uint64[8] memory h,
        uint64[16] memory m,
        uint64[2] memory t,
        bool finalBlock
    ) public view {
        vm.assume(rounds <= 20);
        uint64[8] memory expected = precompile.compress(rounds, h, m, t, finalBlock);
        uint64[8] memory actual = pure_.compress(rounds, h, m, t, finalBlock);
        _assertEq8(actual, expected, "fuzz mismatch");
    }

    function _assertEq8(uint64[8] memory a, uint64[8] memory b, string memory label) internal pure {
        for (uint256 i; i < 8; ++i) {
            require(a[i] == b[i], string.concat(label, ": mismatch at index ", vm.toString(i)));
        }
    }
}
