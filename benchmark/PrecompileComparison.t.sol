// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Sha256Deployed} from "../src/sha256/Sha256Deployed.sol";
import {Ripemd160Deployed} from "../src/ripemd160/Ripemd160Deployed.sol";
import {IdentityDeployed} from "../src/identity/IdentityDeployed.sol";
import {ModexpDeployed} from "../src/modexp/ModexpDeployed.sol";
import {Blake2fDeployed} from "../src/blake2f/Blake2fDeployed.sol";
import {PointEvalDeployed} from "../src/point_eval/PointEvalDeployed.sol";

/// @notice Uniform head-to-head cost for the non-BLS precompiles: the deployed EVM
///         implementation vs the native precompile, both reached by staticcall with
///         the identical raw-bytes calling convention.
///
///         The per-precompile benchmarks elsewhere in this directory measure library
///         call sites (`Xxx.hash(...)` vs `XxxPrecompile.hash(...)`) and report whole
///         test-body gas, which folds in cold-account charges and ABI encoding that
///         differ per suite. Those numbers are useful within a suite but not across
///         suites. This file exists so every precompile is measured the same way and
///         the ratios can be compared directly — including against BlsBenchmark.t.sol,
///         which uses the same harness.
contract PrecompileComparisonTest is Test {
    address constant SHA256 = address(0x02);
    address constant RIPEMD160 = address(0x03);
    address constant IDENTITY = address(0x04);
    address constant MODEXP = address(0x05);
    address constant BLAKE2F = address(0x09);
    address constant POINT_EVAL = address(0x0a);

    address sha256Evm;
    address ripemdEvm;
    address identityEvm;
    address modexpEvm;
    address blake2fEvm;
    address pointEvalEvm;

    // Linear polynomial f(x)=x, z=7, y=7 — same vector as PointEvalBenchmark.
    bytes constant KZG_INPUT =
        hex"014fa3bb4018340ca2fa8eb239e23af6ba465f6d5bc31db78988445da078db76"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"0000000000000000000000000000000000000000000000000000000000000007"
        hex"ad3eb50121139aa34db1d545093ac9374ab7bca2c0f3bf28e27c8dcd8fc7cb42d25926fc0c97b336e9f0fb35e5a04c81"
        hex"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

    function setUp() public {
        sha256Evm = address(new Sha256Deployed());
        ripemdEvm = address(new Ripemd160Deployed());
        identityEvm = address(new IdentityDeployed());
        modexpEvm = address(new ModexpDeployed());
        blake2fEvm = address(new Blake2fDeployed());
        pointEvalEvm = address(new PointEvalDeployed());
    }

    // ── harness ──────────────────────────────────────────────────

    /// Runs the call twice: the first invocation warms the account and yields the
    /// output, the second is measured. Warming cannot be hoisted into setUp via a
    /// cheap failing call — EIP-2929 rolls back access-list changes when a frame
    /// reverts, so the account would read cold again here.
    function _measure(address target, bytes memory data)
        internal view returns (uint256 gasUsed, bytes memory out)
    {
        bool ok;
        (ok, out) = target.staticcall(data);
        require(ok, "call reverted");

        uint256 s = gasleft();
        (ok,) = target.staticcall(data);
        gasUsed = s - gasleft();
        require(ok, "call reverted");
    }

    function _profile(string memory name, address evm, address pre, bytes memory input)
        internal view
    {
        (uint256 evmGas, bytes memory evmOut) = _measure(evm, input);
        (uint256 preGas, bytes memory preOut) = _measure(pre, input);
        assertEq(evmOut, preOut, "EVM output diverges from precompile");

        console.log("---", name);
        console.log("  input bytes  ", input.length);
        console.log("  evm          ", evmGas);
        console.log("  precompile   ", preGas);
        console.log("  ratio        ", evmGas / preGas);
    }

    function _bytes(uint256 n) internal pure returns (bytes memory data) {
        data = new bytes(n);
        for (uint256 i = 0; i < n; i++) data[i] = bytes1(uint8(i));
    }

    // ── 0x02 SHA-256 ─────────────────────────────────────────────

    function test_sha256_32() public view {
        _profile("SHA256 (0x02) 32B", sha256Evm, SHA256, _bytes(32));
    }

    function test_sha256_256() public view {
        _profile("SHA256 (0x02) 256B", sha256Evm, SHA256, _bytes(256));
    }

    // ── 0x03 RIPEMD-160 ──────────────────────────────────────────

    function test_ripemd160_32() public view {
        _profile("RIPEMD160 (0x03) 32B", ripemdEvm, RIPEMD160, _bytes(32));
    }

    function test_ripemd160_256() public view {
        _profile("RIPEMD160 (0x03) 256B", ripemdEvm, RIPEMD160, _bytes(256));
    }

    // ── 0x04 IDENTITY ────────────────────────────────────────────

    function test_identity_32() public view {
        _profile("IDENTITY (0x04) 32B", identityEvm, IDENTITY, _bytes(32));
    }

    function test_identity_256() public view {
        _profile("IDENTITY (0x04) 256B", identityEvm, IDENTITY, _bytes(256));
    }

    // ── 0x05 MODEXP ──────────────────────────────────────────────

    /// EIP-198 encoding: [Bsize][Esize][Msize][base][exp][mod], sizes as 32-byte words.
    function _modexpInput(uint256 bits, bytes memory e) internal pure returns (bytes memory) {
        uint256 len = bits / 8;
        bytes memory b = _odd(len, 2);
        bytes memory m = _odd(len, 1);
        return bytes.concat(abi.encode(len), abi.encode(e.length), abi.encode(len), b, e, m);
    }

    /// Deterministic odd value of `len` bytes with the top bit set.
    function _odd(uint256 len, uint256 seed) internal pure returns (bytes memory v) {
        v = new bytes(len);
        bytes32 h = keccak256(abi.encode(seed));
        for (uint256 i = 0; i < len; i++) {
            if (i % 32 == 0) h = keccak256(abi.encode(h));
            v[i] = h[i % 32];
        }
        v[0] |= 0x80;
        v[len - 1] |= 0x01;
    }

    function test_modexp_2048_e65537() public view {
        _profile("MODEXP (0x05) 2048b e=65537", modexpEvm, MODEXP, _modexpInput(2048, hex"010001"));
    }

    function test_modexp_4096_e65537() public view {
        _profile("MODEXP (0x05) 4096b e=65537", modexpEvm, MODEXP, _modexpInput(4096, hex"010001"));
    }

    // ── 0x09 BLAKE2F ─────────────────────────────────────────────

    /// Build a 213-byte EIP-152 input from structured parameters.
    function _blake2fInput(uint32 rounds) internal pure returns (bytes memory input) {
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
        m[0] = 0x0000000000636261; // "abc"
        uint64[2] memory t;
        t[0] = 3;

        input = new bytes(213);
        assembly {
            let buf := add(input, 0x20)

            mstore8(buf, shr(24, rounds))
            mstore8(add(buf, 1), shr(16, rounds))
            mstore8(add(buf, 2), shr(8, rounds))
            mstore8(add(buf, 3), rounds)

            function swap64(x) -> r {
                x := and(x, 0xffffffffffffffff)
                x := or(shl(8, and(x, 0x00FF00FF00FF00FF)), shr(8, and(x, 0xFF00FF00FF00FF00)))
                x := or(shl(16, and(x, 0x0000FFFF0000FFFF)), shr(16, and(x, 0xFFFF0000FFFF0000)))
                r := or(shl(32, and(x, 0x00000000FFFFFFFF)), shr(32, and(x, 0xFFFFFFFF00000000)))
            }

            let ptr := add(buf, 4)
            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                mstore(ptr, shl(192, swap64(mload(add(h, mul(i, 0x20))))))
                ptr := add(ptr, 8)
            }
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                mstore(ptr, shl(192, swap64(mload(add(m, mul(i, 0x20))))))
                ptr := add(ptr, 8)
            }
            for { let i := 0 } lt(i, 2) { i := add(i, 1) } {
                mstore(ptr, shl(192, swap64(mload(add(t, mul(i, 0x20))))))
                ptr := add(ptr, 8)
            }
            mstore8(add(buf, 212), 1) // finalBlock
        }
    }

    function test_blake2f_12rounds() public view {
        _profile("BLAKE2F (0x09) 12r", blake2fEvm, BLAKE2F, _blake2fInput(12));
    }

    function test_blake2f_100rounds() public view {
        _profile("BLAKE2F (0x09) 100r", blake2fEvm, BLAKE2F, _blake2fInput(100));
    }

    // ── 0x0a POINT EVALUATION ────────────────────────────────────

    function test_point_eval() public view {
        _profile("POINT_EVAL (0x0a)", pointEvalEvm, POINT_EVAL, KZG_INPUT);
    }
}
