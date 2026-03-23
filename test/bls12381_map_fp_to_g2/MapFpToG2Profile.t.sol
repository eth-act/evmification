// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {Fp} from "../../src/bls12381/Fp.sol";
import {Fp2} from "../../src/bls12381/Fp2.sol";
import {MapFpToG2} from "../../src/bls12381_map_fp_to_g2/MapFpToG2.sol";

/// @dev Wrapper that calls MapFpToG2.mapToG2 and measures total gas.
contract MapFpToG2Caller {
    function mapToG2(bytes calldata input) external pure returns (bytes memory) {
        return MapFpToG2.mapToG2(input);
    }
}

contract MapFpToG2ProfileTest is Test {
    MapFpToG2Caller caller;

    function setUp() public {
        caller = new MapFpToG2Caller();
    }

    // ── Helper ──────────────────────────────────────────────────────

    function _makeInput(uint256 c0, uint256 c1) private pure returns (bytes memory input) {
        input = new bytes(128);
        assembly {
            let ptr := add(input, 0x20)
            mstore(add(ptr, 0x20), c0)
            mstore(add(ptr, 0x60), c1)
        }
    }

    // ── Test 1: Fp primitive costs ──────────────────────────────────

    function test_profile_fp_ops() public view {
        bytes memory a = hex"0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0";
        bytes memory b = hex"17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb";

        uint256 g;

        g = gasleft();
        Fp.add(a, b);
        console.log("Fp.add:       ", g - gasleft());

        g = gasleft();
        Fp.sub(a, b);
        console.log("Fp.sub:       ", g - gasleft());

        g = gasleft();
        Fp.neg(a);
        console.log("Fp.neg:       ", g - gasleft());

        g = gasleft();
        Fp.mul(a, b);
        console.log("Fp.mul:       ", g - gasleft());

        g = gasleft();
        Fp.sqr(a);
        console.log("Fp.sqr:       ", g - gasleft());

        g = gasleft();
        Fp.inv(a);
        console.log("Fp.inv:       ", g - gasleft());

        g = gasleft();
        Fp.sqrt(a);
        console.log("Fp.sqrt:      ", g - gasleft());

        g = gasleft();
        Fp.isSquare(a);
        console.log("Fp.isSquare:  ", g - gasleft());

        g = gasleft();
        Fp.fromUint256(42);
        console.log("Fp.fromUint256:", g - gasleft());

        g = gasleft();
        Fp.sgn0(a);
        console.log("Fp.sgn0:      ", g - gasleft());

        g = gasleft();
        Fp.eq(a, b);
        console.log("Fp.eq:        ", g - gasleft());

        g = gasleft();
        Fp.isZero(a);
        console.log("Fp.isZero:    ", g - gasleft());
    }

    // ── Test 2: Fp2 primitive costs ─────────────────────────────────

    function test_profile_fp2_ops() public view {
        bytes memory a = hex"0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0";
        bytes memory b = hex"17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb";

        Fp2.Element memory x = Fp2.fromFp(a, b);
        Fp2.Element memory y = Fp2.fromFp(b, a);

        uint256 g;

        g = gasleft();
        Fp2.add(x, y);
        console.log("Fp2.add:      ", g - gasleft());

        g = gasleft();
        Fp2.sub(x, y);
        console.log("Fp2.sub:      ", g - gasleft());

        g = gasleft();
        Fp2.neg(x);
        console.log("Fp2.neg:      ", g - gasleft());

        g = gasleft();
        Fp2.mul(x, y);
        console.log("Fp2.mul:      ", g - gasleft());

        g = gasleft();
        Fp2.sqr(x);
        console.log("Fp2.sqr:      ", g - gasleft());

        g = gasleft();
        Fp2.inv(x);
        console.log("Fp2.inv:      ", g - gasleft());

        g = gasleft();
        Fp2.sqrt(x);
        console.log("Fp2.sqrt:     ", g - gasleft());

        g = gasleft();
        Fp2.mulFp(x, a);
        console.log("Fp2.mulFp:    ", g - gasleft());

        g = gasleft();
        Fp2.conjugate(x);
        console.log("Fp2.conjugate:", g - gasleft());

        g = gasleft();
        Fp2.mulByI(x);
        console.log("Fp2.mulByI:   ", g - gasleft());

        g = gasleft();
        Fp2.isZero(x);
        console.log("Fp2.isZero:   ", g - gasleft());

        g = gasleft();
        Fp2.eq(x, y);
        console.log("Fp2.eq:       ", g - gasleft());

        g = gasleft();
        Fp2.sgn0(x);
        console.log("Fp2.sgn0:     ", g - gasleft());
    }

    // ── Test 3: Total mapToG2 gas ───────────────────────────────────

    function test_profile_mapToG2_total() public view {
        bytes memory input = _makeInput(7, 3);

        uint256 g = gasleft();
        MapFpToG2.mapToG2(input);
        uint256 totalGas = g - gasleft();

        console.log("mapToG2 total (library):", totalGas);

        // Also measure via external call (includes calldata + return overhead)
        g = gasleft();
        caller.mapToG2(input);
        uint256 externalGas = g - gasleft();

        console.log("mapToG2 total (external):", externalGas);
    }

    // ── Test 4: Phase-level profiling via duplicated logic ──────────
    //
    // Since MapFpToG2's internal functions are private, we duplicate the
    // top-level mapToG2 flow here with gasleft() snapshots at each phase
    // boundary. The sub-functions are called via MapFpToG2.mapToG2 indirectly.
    //
    // Strategy: We can't call _sswuProjective etc. directly, but we CAN
    // measure the total and then measure sub-computations that approximate
    // each phase using Fp2 operations we know each phase performs.
    //
    // Better strategy: measure cumulative gas by running partial computations
    // that stop at each phase boundary. We do this by creating contracts
    // with modified mapToG2 that returns early after each phase.
    //
    // Simplest correct strategy: use gasleft() in a single function that
    // inlines all the logic. We import the Fp2 library and rewrite the
    // mapToG2 flow with gas snapshots.

    function test_profile_mapToG2_phases() public view {
        bytes memory input = _makeInput(7, 3);

        // Extract Fp2 element from input
        bytes memory c0 = new bytes(48);
        bytes memory c1 = new bytes(48);
        assembly {
            let src := add(input, 0x30)
            let dst := add(c0, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
            src := add(input, 0x70)
            dst := add(c1, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }
        Fp2.Element memory u = Fp2.fromFp(c0, c1);

        uint256 g0;
        uint256 g1;
        uint256 g2;
        uint256 g3;
        uint256 g4;

        // ── Phase 1: SWU ────────────────────────────────────────────
        g0 = gasleft();
        (Fp2.Element memory xN, Fp2.Element memory xD, Fp2.Element memory yp) = _sswuProjective(u);
        g1 = gasleft();

        // ── Phase 2: Isogeny ────────────────────────────────────────
        (Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ) = _iso3Projective(xN, xD, yp);
        g2 = gasleft();

        // ── Phase 3: Cofactor clearing ──────────────────────────────
        (Fp2.Element memory rx, Fp2.Element memory ry) = _clearCofactorJac(jX, jY, jZ);
        g3 = gasleft();

        // ── Phase 4: Encode to bytes ────────────────────────────────
        bytes memory output = new bytes(256);
        assembly {
            let dst := add(output, 0x20)
            let src := mload(rx)
            src := add(src, 0x20)
            mstore(add(dst, 0x10), mload(src))
            mstore(add(dst, 0x30), mload(add(src, 0x20)))
            src := mload(add(rx, 0x20))
            src := add(src, 0x20)
            mstore(add(dst, 0x50), mload(src))
            mstore(add(dst, 0x70), mload(add(src, 0x20)))
            src := mload(ry)
            src := add(src, 0x20)
            mstore(add(dst, 0x90), mload(src))
            mstore(add(dst, 0xB0), mload(add(src, 0x20)))
            src := mload(add(ry, 0x20))
            src := add(src, 0x20)
            mstore(add(dst, 0xD0), mload(src))
            mstore(add(dst, 0xF0), mload(add(src, 0x20)))
        }
        g4 = gasleft();

        // Verify correctness against reference
        bytes memory expected = MapFpToG2.mapToG2(input);
        assertEq(output, expected, "profiled output mismatch");

        uint256 gasSWU = g0 - g1;
        uint256 gasIsogeny = g1 - g2;
        uint256 gasCofactor = g2 - g3;
        uint256 gasEncode = g3 - g4;
        uint256 gasTotal = g0 - g4;

        console.log("=== mapToG2 Phase Breakdown ===");
        console.log("SWU:              ", gasSWU);
        console.log("Isogeny:          ", gasIsogeny);
        console.log("Cofactor clearing:", gasCofactor);
        console.log("Encode:           ", gasEncode);
        console.log("Total (phases):   ", gasTotal);
        console.log("SWU %%:            ", gasSWU * 100 / gasTotal);
        console.log("Isogeny %%:        ", gasIsogeny * 100 / gasTotal);
        console.log("Cofactor %%:       ", gasCofactor * 100 / gasTotal);
        console.log("Encode %%:         ", gasEncode * 100 / gasTotal);
    }

    // ════════════════════════════════════════════════════════════════
    // Duplicated private functions from MapFpToG2 (needed for phase profiling)
    // ════════════════════════════════════════════════════════════════

    // ── Constants ───────────────────────────────────────────────────

    function _aPrime() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(new bytes(48), Fp.fromUint256(240));
    }

    function _bPrime() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(Fp.fromUint256(1012), Fp.fromUint256(1012));
    }

    function _z() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(Fp.neg(Fp.fromUint256(2)), Fp.neg(Fp.fromUint256(1)));
    }

    function _fp2(bytes memory c0, bytes memory c1) private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(c0, c1);
    }

    function _psiCoeffX() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(
            new bytes(48),
            hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"
        );
    }

    function _psiCoeffY() private pure returns (Fp2.Element memory) {
        return Fp2.fromFp(
            hex"135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2",
            hex"06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09"
        );
    }

    bytes constant PSI2_COEFF_X =
        hex"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac";

    // ── SWU ─────────────────────────────────────────────────────────

    function _sswuProjective(Fp2.Element memory u)
        private
        pure
        returns (Fp2.Element memory xN, Fp2.Element memory xD, Fp2.Element memory y)
    {
        Fp2.Element memory A = _aPrime();
        Fp2.Element memory B = _bPrime();
        Fp2.Element memory Z = _z();
        Fp2.Element memory ONE_FP2 = Fp2.one();

        Fp2.Element memory tv1 = Fp2.sqr(u);
        tv1 = Fp2.mul(Z, tv1);
        Fp2.Element memory tv2 = Fp2.sqr(tv1);
        tv2 = Fp2.add(tv2, tv1);
        Fp2.Element memory tv3 = Fp2.add(tv2, ONE_FP2);
        tv3 = Fp2.mul(B, tv3);
        Fp2.Element memory tv4 = Fp2.isZero(tv2) ? Z : Fp2.neg(tv2);
        tv4 = Fp2.mul(A, tv4);
        tv2 = Fp2.sqr(tv3);
        Fp2.Element memory tv6 = Fp2.sqr(tv4);
        Fp2.Element memory tv5 = Fp2.mul(A, tv6);
        tv2 = Fp2.add(tv2, tv5);
        tv2 = Fp2.mul(tv2, tv3);
        tv6 = Fp2.mul(tv6, tv4);
        tv5 = Fp2.mul(B, tv6);
        tv2 = Fp2.add(tv2, tv5);
        xN = Fp2.mul(tv1, tv3);
        (bool is_gx1_square, Fp2.Element memory y1) = _sqrtRatioFp2(tv2, tv6);
        y = Fp2.mul(tv1, u);
        y = Fp2.mul(y, y1);
        xN = is_gx1_square ? tv3 : xN;
        y = is_gx1_square ? y1 : y;
        if (Fp2.sgn0(u) != Fp2.sgn0(y)) {
            y = Fp2.neg(y);
        }
        xD = tv4;
    }

    function _sqrtRatioFp2(Fp2.Element memory u, Fp2.Element memory v)
        private
        pure
        returns (bool, Fp2.Element memory)
    {
        Fp2.Element memory vInv = Fp2.inv(v);
        Fp2.Element memory uOverV = Fp2.mul(u, vInv);
        (bool exists, Fp2.Element memory s) = Fp2.sqrt(uOverV);
        if (exists) {
            return (true, s);
        }
        Fp2.Element memory Z = _z();
        Fp2.Element memory zUOverV = Fp2.mul(Z, uOverV);
        (exists, s) = Fp2.sqrt(zUOverV);
        return (false, s);
    }

    // ── Isogeny ─────────────────────────────────────────────────────

    function _iso3Projective(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element memory yp)
        private
        pure
        returns (Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ)
    {
        (Fp2.Element memory xNumH, ) = _evalPolyHom(N, D, _xNumCoeffs());
        (Fp2.Element memory xDenH, ) = _evalPolyMonicHom(N, D, _xDenCoeffs());
        (Fp2.Element memory yNumH, ) = _evalPolyHom(N, D, _yNumCoeffs());
        (Fp2.Element memory yDenH, ) = _evalPolyMonicHom(N, D, _yDenCoeffs());

        jZ = Fp2.mul(Fp2.mul(xDenH, D), yDenH);
        jX = Fp2.mul(Fp2.mul(xNumH, yDenH), jZ);
        Fp2.Element memory jZ2 = Fp2.sqr(jZ);
        jY = Fp2.mul(Fp2.mul(Fp2.mul(yp, yNumH), Fp2.mul(xDenH, D)), jZ2);
    }

    function _evalPolyHom(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element[] memory coeffs)
        private
        pure
        returns (Fp2.Element memory num, Fp2.Element memory den)
    {
        num = coeffs[0];
        den = Fp2.one();
        for (uint256 i = 1; i < coeffs.length; i++) {
            den = Fp2.mul(den, D);
            num = Fp2.add(Fp2.mul(num, N), Fp2.mul(coeffs[i], den));
        }
    }

    function _evalPolyMonicHom(Fp2.Element memory N, Fp2.Element memory D, Fp2.Element[] memory coeffs)
        private
        pure
        returns (Fp2.Element memory num, Fp2.Element memory den)
    {
        num = Fp2.one();
        den = Fp2.one();
        for (uint256 i = 0; i < coeffs.length; i++) {
            den = Fp2.mul(den, D);
            num = Fp2.add(Fp2.mul(num, N), Fp2.mul(coeffs[i], den));
        }
    }

    // ── Isogeny coefficients ────────────────────────────────────────

    function _xNumCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](4);
        c[0] = _fp2(
            hex"171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1",
            new bytes(48)
        );
        c[1] = _fp2(
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e",
            hex"08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"
        );
        c[2] = _fp2(
            new bytes(48),
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"
        );
        c[3] = _fp2(
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6",
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"
        );
    }

    function _xDenCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](2);
        c[0] = _fp2(
            Fp.fromUint256(12),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"
        );
        c[1] = _fp2(
            new bytes(48),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"
        );
    }

    function _yNumCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](4);
        c[0] = _fp2(
            hex"124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10",
            new bytes(48)
        );
        c[1] = _fp2(
            hex"11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c",
            hex"08ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"
        );
        c[2] = _fp2(
            new bytes(48),
            hex"05c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"
        );
        c[3] = _fp2(
            hex"1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706",
            hex"1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"
        );
    }

    function _yDenCoeffs() private pure returns (Fp2.Element[] memory c) {
        c = new Fp2.Element[](3);
        c[0] = _fp2(
            Fp.fromUint256(18),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"
        );
        c[1] = _fp2(
            new bytes(48),
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"
        );
        c[2] = _fp2(
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb",
            hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
        );
    }

    // ── Cofactor clearing ───────────────────────────────────────────

    function _clearCofactorJac(Fp2.Element memory jX, Fp2.Element memory jY, Fp2.Element memory jZ)
        private
        pure
        returns (Fp2.Element memory, Fp2.Element memory)
    {
        (Fp2.Element memory px, Fp2.Element memory py) = _jacToAffine(jX, jY, jZ);

        Fp2.Element memory ONE = Fp2.one();

        (Fp2.Element memory psiPx, Fp2.Element memory psiPy) = _psiAffine(px, py);

        (Fp2.Element memory twoJX, Fp2.Element memory twoJY, Fp2.Element memory twoJZ) = _g2JacDouble(px, py, ONE);
        (Fp2.Element memory psi2_2X, Fp2.Element memory psi2_2Y, Fp2.Element memory psi2_2Z) = _psi2Jac(twoJX, twoJY, twoJZ);

        (Fp2.Element memory xPX, Fp2.Element memory xPY, Fp2.Element memory xPZ) = _mulBySeedJac(px, py);

        (Fp2.Element memory outX, Fp2.Element memory outY, Fp2.Element memory outZ) =
            _g2JacAddMixed(psi2_2X, psi2_2Y, psi2_2Z, px, Fp2.neg(py));
        (outX, outY, outZ) = _g2JacAddMixed(outX, outY, outZ, psiPx, Fp2.neg(psiPy));

        (Fp2.Element memory t0X, Fp2.Element memory t0Y, Fp2.Element memory t0Z) =
            _g2JacAddMixed(xPX, xPY, xPZ, px, py);

        (t0X, t0Y, t0Z) = _g2JacAddMixed(t0X, t0Y, t0Z, psiPx, Fp2.neg(psiPy));

        (Fp2.Element memory t1X, Fp2.Element memory t1Y, Fp2.Element memory t1Z) =
            _mulBySeedJacFull(t0X, t0Y, t0Z);

        (outX, outY, outZ) = _g2JacAdd(outX, outY, outZ, t1X, t1Y, t1Z);

        return _jacToAffine(outX, outY, outZ);
    }

    function _jacToAffine(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory x, Fp2.Element memory y)
    {
        Fp2.Element memory zInv = Fp2.inv(Z);
        Fp2.Element memory zInv2 = Fp2.sqr(zInv);
        Fp2.Element memory zInv3 = Fp2.mul(zInv2, zInv);
        x = Fp2.mul(X, zInv2);
        y = Fp2.mul(Y, zInv3);
    }

    function _psiAffine(Fp2.Element memory px, Fp2.Element memory py)
        private
        pure
        returns (Fp2.Element memory rx, Fp2.Element memory ry)
    {
        rx = Fp2.mul(Fp2.conjugate(px), _psiCoeffX());
        ry = Fp2.mul(Fp2.conjugate(py), _psiCoeffY());
    }

    function _psi2Jac(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory, Fp2.Element memory, Fp2.Element memory)
    {
        return (Fp2.mulFp(X, PSI2_COEFF_X), Fp2.neg(Y), Z);
    }

    function _mulBySeedJac(Fp2.Element memory px, Fp2.Element memory py)
        private
        pure
        returns (Fp2.Element memory rX, Fp2.Element memory rY, Fp2.Element memory rZ)
    {
        uint64 seed = 0xd201000000010000;
        rX = px;
        rY = py;
        rZ = Fp2.one();
        for (uint256 i = 62; i < 64; ) {
            (rX, rY, rZ) = _g2JacDouble(rX, rY, rZ);
            if ((seed >> i) & 1 == 1) {
                (rX, rY, rZ) = _g2JacAddMixed(rX, rY, rZ, px, py);
            }
            unchecked {
                if (i == 0) break;
                --i;
            }
        }
    }

    function _mulBySeedJacFull(Fp2.Element memory X, Fp2.Element memory Y, Fp2.Element memory Z)
        private
        pure
        returns (Fp2.Element memory rX, Fp2.Element memory rY, Fp2.Element memory rZ)
    {
        (Fp2.Element memory ax, Fp2.Element memory ay) = _jacToAffine(X, Y, Z);
        uint64 seed = 0xd201000000010000;
        rX = ax;
        rY = ay;
        rZ = Fp2.one();
        for (uint256 i = 62; i < 64; ) {
            (rX, rY, rZ) = _g2JacDouble(rX, rY, rZ);
            if ((seed >> i) & 1 == 1) {
                (rX, rY, rZ) = _g2JacAddMixed(rX, rY, rZ, ax, ay);
            }
            unchecked {
                if (i == 0) break;
                --i;
            }
        }
    }

    // ── Jacobian point arithmetic ───────────────────────────────────

    function _g2JacDouble(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        Fp2.Element memory A = Fp2.sqr(X1);
        Fp2.Element memory B = Fp2.sqr(Y1);
        Fp2.Element memory C = Fp2.sqr(B);
        Fp2.Element memory t = Fp2.sqr(Fp2.add(X1, B));
        t = Fp2.sub(Fp2.sub(t, A), C);
        Fp2.Element memory D = Fp2.add(t, t);
        Fp2.Element memory E = Fp2.add(A, Fp2.add(A, A));
        Fp2.Element memory F = Fp2.sqr(E);
        X3 = Fp2.sub(F, Fp2.add(D, D));
        Fp2.Element memory eightC = Fp2.add(C, C);
        eightC = Fp2.add(eightC, eightC);
        eightC = Fp2.add(eightC, eightC);
        Y3 = Fp2.sub(Fp2.mul(E, Fp2.sub(D, X3)), eightC);
        Z3 = Fp2.add(Fp2.mul(Y1, Z1), Fp2.mul(Y1, Z1));
    }

    function _g2JacAddMixed(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1,
        Fp2.Element memory x2,
        Fp2.Element memory y2
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        if (Fp2.isZero(Z1)) {
            return (x2, y2, Fp2.one());
        }
        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);
        Fp2.Element memory U2 = Fp2.mul(x2, Z1Z1);
        Fp2.Element memory S2 = Fp2.mul(y2, Fp2.mul(Z1, Z1Z1));
        Fp2.Element memory H = Fp2.sub(U2, X1);
        Fp2.Element memory HH = Fp2.sqr(H);
        Fp2.Element memory I = Fp2.add(HH, HH);
        I = Fp2.add(I, I);
        Fp2.Element memory J = Fp2.mul(H, I);
        Fp2.Element memory r = Fp2.sub(S2, Y1);
        r = Fp2.add(r, r);
        Fp2.Element memory V = Fp2.mul(X1, I);
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));
        Fp2.Element memory Y1J = Fp2.mul(Y1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(Y1J, Y1J));
        Z3 = Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, H)), Z1Z1), HH);
    }

    function _g2JacAdd(
        Fp2.Element memory X1,
        Fp2.Element memory Y1,
        Fp2.Element memory Z1,
        Fp2.Element memory X2,
        Fp2.Element memory Y2,
        Fp2.Element memory Z2
    )
        private
        pure
        returns (Fp2.Element memory X3, Fp2.Element memory Y3, Fp2.Element memory Z3)
    {
        if (Fp2.isZero(Z1)) {
            return (X2, Y2, Z2);
        }
        if (Fp2.isZero(Z2)) {
            return (X1, Y1, Z1);
        }
        Fp2.Element memory Z1Z1 = Fp2.sqr(Z1);
        Fp2.Element memory Z2Z2 = Fp2.sqr(Z2);
        Fp2.Element memory U1 = Fp2.mul(X1, Z2Z2);
        Fp2.Element memory U2 = Fp2.mul(X2, Z1Z1);
        Fp2.Element memory S1 = Fp2.mul(Y1, Fp2.mul(Z2, Z2Z2));
        Fp2.Element memory S2 = Fp2.mul(Y2, Fp2.mul(Z1, Z1Z1));
        Fp2.Element memory H = Fp2.sub(U2, U1);
        Fp2.Element memory II = Fp2.add(H, H);
        II = Fp2.sqr(II);
        Fp2.Element memory J = Fp2.mul(H, II);
        Fp2.Element memory r = Fp2.sub(S2, S1);
        r = Fp2.add(r, r);
        Fp2.Element memory V = Fp2.mul(U1, II);
        X3 = Fp2.sub(Fp2.sub(Fp2.sqr(r), J), Fp2.add(V, V));
        Fp2.Element memory S1J = Fp2.mul(S1, J);
        Y3 = Fp2.sub(Fp2.mul(r, Fp2.sub(V, X3)), Fp2.add(S1J, S1J));
        Z3 = Fp2.mul(
            Fp2.sub(Fp2.sub(Fp2.sqr(Fp2.add(Z1, Z2)), Z1Z1), Z2Z2),
            H
        );
    }
}
