// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2 as console} from "forge-std/Test.sol";
import {G1AddDeployed} from "../../src/bls12381_g1add/G1AddDeployed.sol";
import {G1MsmDeployed} from "../../src/bls12381_g1msm/G1MsmDeployed.sol";
import {G2AddDeployed} from "../../src/bls12381_g2add/G2AddDeployed.sol";
import {G2MsmDeployed} from "../../src/bls12381_g2msm/G2MsmDeployed.sol";
import {MapFpToG1Deployed} from "../../src/bls12381_map_fp_to_g1/MapFpToG1Deployed.sol";
import {MapFpToG2Deployed} from "../../src/bls12381_map_fp_to_g2/MapFpToG2Deployed.sol";
import {PairingDeployed} from "../../src/bls12381_pairing/PairingDeployed.sol";

/// @notice Head-to-head cost of each EIP-2537 BLS12-381 precompile: the deployed
///         EVM implementation vs the native precompile. Both sides are reached by
///         staticcall with the identical raw-bytes calling convention, so the same
///         call overhead sits on each and cancels out of the ratio.
///
///         Inputs are derived from the native MAP_FP_TO_G1 / MAP_FP_TO_G2
///         precompiles rather than hardcoded, which guarantees the points are on
///         the curve and in the correct subgroup — the pairing and MSM
///         implementations reject anything that is not.
contract BlsBenchmarkTest is Test {
    address constant G1ADD = address(0x0b);
    address constant G1MSM = address(0x0c);
    address constant G2ADD = address(0x0d);
    address constant G2MSM = address(0x0e);
    address constant PAIRING = address(0x0f);
    address constant MAP_G1 = address(0x10);
    address constant MAP_G2 = address(0x11);

    address g1addEvm;
    address g1msmEvm;
    address g2addEvm;
    address g2msmEvm;
    address pairingEvm;
    address mapG1Evm;
    address mapG2Evm;

    bytes g1a; // 128-byte G1 point
    bytes g1b;
    bytes g2a; // 256-byte G2 point
    bytes g2b;

    function setUp() public {
        g1addEvm = address(new G1AddDeployed());
        g1msmEvm = address(new G1MsmDeployed());
        g2addEvm = address(new G2AddDeployed());
        g2msmEvm = address(new G2MsmDeployed());
        pairingEvm = address(new PairingDeployed());
        mapG1Evm = address(new MapFpToG1Deployed());
        mapG2Evm = address(new MapFpToG2Deployed());

        g1a = _call(MAP_G1, _fp(3), 128);
        g1b = _call(MAP_G1, _fp(5), 128);
        g2a = _call(MAP_G2, _fp2(3), 256);
        g2b = _call(MAP_G2, _fp2(5), 256);
    }

    // ── helpers ──────────────────────────────────────────────────

    function _call(address target, bytes memory data, uint256 expectedLen)
        internal view returns (bytes memory out)
    {
        bool ok;
        (ok, out) = target.staticcall(data);
        require(ok, "call reverted");
        require(out.length == expectedLen, "unexpected output length");
    }

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

    /// Fp element in EIP-2537 form: 64 bytes = 16 zero pad || 48-byte big-endian.
    /// Small values are trivially below the field modulus.
    function _fp(uint256 v) internal pure returns (bytes memory out) {
        out = new bytes(64);
        assembly { mstore(add(out, 0x40), v) } // last 32 bytes
    }

    /// Fp2 element: two padded Fp elements, c0 then c1.
    function _fp2(uint256 v) internal pure returns (bytes memory) {
        return bytes.concat(_fp(v), _fp(v + 1));
    }

    /// 32-byte big-endian scalar.
    function _scalar(uint256 v) internal pure returns (bytes memory) {
        return abi.encode(v);
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

    // ── benchmarks ───────────────────────────────────────────────

    function test_g1add() public view {
        _profile("G1ADD (0x0b)", g1addEvm, G1ADD, bytes.concat(g1a, g1b));
    }

    function test_g2add() public view {
        _profile("G2ADD (0x0d)", g2addEvm, G2ADD, bytes.concat(g2a, g2b));
    }

    function test_map_fp_to_g1() public view {
        _profile("MAP_FP_TO_G1 (0x10)", mapG1Evm, MAP_G1, _fp(7));
    }

    function test_map_fp_to_g2() public view {
        _profile("MAP_FP_TO_G2 (0x11)", mapG2Evm, MAP_G2, _fp2(7));
    }

    function test_g1msm_k1() public view {
        _profile("G1MSM k=1 (0x0c)", g1msmEvm, G1MSM, bytes.concat(g1a, _scalar(12345)));
    }

    function test_g1msm_k2() public view {
        _profile(
            "G1MSM k=2 (0x0c)",
            g1msmEvm,
            G1MSM,
            bytes.concat(g1a, _scalar(12345), g1b, _scalar(67890))
        );
    }

    function test_g2msm_k1() public view {
        _profile("G2MSM k=1 (0x0e)", g2msmEvm, G2MSM, bytes.concat(g2a, _scalar(12345)));
    }

    function test_g2msm_k2() public view {
        _profile(
            "G2MSM k=2 (0x0e)",
            g2msmEvm,
            G2MSM,
            bytes.concat(g2a, _scalar(12345), g2b, _scalar(67890))
        );
    }

    function test_pairing_k1() public view {
        _profile("PAIRING k=1 (0x0f)", pairingEvm, PAIRING, bytes.concat(g1a, g2a));
    }

    function test_pairing_k2() public view {
        _profile(
            "PAIRING k=2 (0x0f)",
            pairingEvm,
            PAIRING,
            bytes.concat(g1a, g2a, g1b, g2b)
        );
    }
}
