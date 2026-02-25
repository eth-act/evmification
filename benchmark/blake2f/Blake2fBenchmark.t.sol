// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2fPrecompile} from "../../src/blake2f/Blake2fPrecompile.sol";
import {Blake2f} from "../../src/blake2f/Blake2f.sol";

contract Blake2fPrecompileBenchCaller {
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

contract Blake2fPureBenchCaller {
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

contract Blake2fBenchmarkTest is Test {
    Blake2fPrecompileBenchCaller precompileCaller;
    Blake2fPureBenchCaller pureCaller;

    // Standard BLAKE2b("abc") initial state
    uint64[8] h;
    uint64[16] m;
    uint64[2] t;

    function setUp() public {
        precompileCaller = new Blake2fPrecompileBenchCaller();
        pureCaller = new Blake2fPureBenchCaller();

        h[0] = 0x6a09e667f2bdc948;
        h[1] = 0xbb67ae8584caa73b;
        h[2] = 0x3c6ef372fe94f82b;
        h[3] = 0xa54ff53a5f1d36f1;
        h[4] = 0x510e527fade682d1;
        h[5] = 0x9b05688c2b3e6c1f;
        h[6] = 0x1f83d9abfb41bd6b;
        h[7] = 0x5be0cd19137e2179;
        m[0] = 0x0000000000636261;
        t[0] = 3;
    }

    // ── Precompile benchmarks ──

    function test_precompile_1round() public view {
        precompileCaller.compress(1, h, m, t, true);
    }

    function test_precompile_12rounds() public view {
        precompileCaller.compress(12, h, m, t, true);
    }

    function test_precompile_100rounds() public view {
        precompileCaller.compress(100, h, m, t, true);
    }

    // ── Pure benchmarks ──

    function test_pure_1round() public view {
        pureCaller.compress(1, h, m, t, true);
    }

    function test_pure_12rounds() public view {
        pureCaller.compress(12, h, m, t, true);
    }

    function test_pure_100rounds() public view {
        pureCaller.compress(100, h, m, t, true);
    }
}
