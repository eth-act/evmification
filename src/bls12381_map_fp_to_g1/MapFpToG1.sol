// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Fp} from "../bls12381/Fp.sol";

/// @title MapFpToG1
/// @notice Pure Solidity implementation of MAP_FP_TO_G1 (EIP-2537, address 0x10).
/// @dev Implements simplified SWU map to isogenous curve E'1 followed by 11-isogeny to E1.
library MapFpToG1 {
    // ── Isogenous curve E'1 constants: y² = x³ + A'x + B' ──────────

    bytes constant A_PRIME =
        hex"00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d";

    bytes constant B_PRIME =
        hex"12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0";

    /// @dev Z = 11 for BLS12-381 G1 SWU map.
    bytes constant Z =
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b";

    /// @dev sqrt(-Z) = sqrt(-11) mod p = sqrt(p - 11) mod p.
    bytes constant SQRT_MINUS_Z =
        hex"04610e003bd3ac94dfa9246c390d7a78942602029175a4ca366d601f33f3946e3ed39794735c38315d874bc1d70637c3";

    // ── ONE constant ────────────────────────────────────────────────

    bytes constant ONE =
        hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

    /// @dev B = 4 for BLS12-381 E1: y^2 = x^3 + 4.
    bytes constant B_E1 =
        hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004";

    /// @dev THREE constant for point doubling.
    bytes constant THREE =
        hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003";

    /// @dev TWO constant for point doubling.
    bytes constant TWO =
        hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";

    // ── Main entry point ────────────────────────────────────────────

    /// @notice Map a field element to a G1 point (EIP-2537 format).
    /// @param input 64 bytes: 16-byte zero padding + 48-byte Fp element.
    /// @return output 128 bytes: two 64-byte padded Fp elements (x, y).
    function mapToG1(bytes memory input) internal pure returns (bytes memory output) {
        require(input.length == 64, "invalid input length");

        // Extract 48-byte field element (skip 16-byte zero padding)
        bytes memory u = new bytes(48);
        assembly {
            let src := add(input, 0x30) // skip 32 (length) + 16 (padding)
            let dst := add(u, 0x20)
            mstore(dst, mload(src))
            mstore(add(dst, 0x20), mload(add(src, 0x20)))
        }

        // SWU returns projective x = xN/xD and y
        (bytes memory xN, bytes memory xD, bytes memory yp) = _sswuProjective(u);

        // Isogeny in projective form, outputs Jacobian point
        (bytes memory jX, bytes memory jY, bytes memory jZ) = _iso11Projective(xN, xD, yp);

        // Clear cofactor in Jacobian coordinates
        (bytes memory x, bytes memory y) = _clearCofactorJac(jX, jY, jZ);

        // Encode as 128-byte output: 16-zero-pad || x(48) || 16-zero-pad || y(48)
        output = new bytes(128);
        assembly {
            let dst := add(output, 0x20)
            // x: 16 zero bytes already there, then 48 bytes of x
            let xSrc := add(x, 0x20)
            mstore(add(dst, 0x10), mload(xSrc))
            mstore(add(dst, 0x30), mload(add(xSrc, 0x20)))
            // y: offset 64, 16 zero bytes already there, then 48 bytes of y
            let ySrc := add(y, 0x20)
            mstore(add(dst, 0x50), mload(ySrc))
            mstore(add(dst, 0x70), mload(add(ySrc, 0x20)))
        }
    }

    // ── Simplified SWU (RFC 9380, Appendix F.2) — projective output ──

    /// @dev Returns (xN, xD, y) where x' = xN/xD, avoiding the inversion.
    function _sswuProjective(bytes memory u) private pure returns (bytes memory xN, bytes memory xD, bytes memory y) {
        // Step 1: tv1 = u²
        bytes memory tv1 = Fp.sqr(u);
        // Step 2: tv1 = Z * tv1
        tv1 = Fp.mul(Z, tv1);
        // Step 3: tv2 = tv1²
        bytes memory tv2 = Fp.sqr(tv1);
        // Step 4: tv2 = tv2 + tv1
        tv2 = Fp.add(tv2, tv1);
        // Step 5: tv3 = tv2 + 1
        bytes memory tv3 = Fp.add(tv2, ONE);
        // Step 6: tv3 = B' * tv3
        tv3 = Fp.mul(B_PRIME, tv3);
        // Step 7: tv4 = CMOV(Z, -tv2, tv2 != 0)
        bytes memory tv4 = Fp.isZero(tv2) ? Z : Fp.neg(tv2);
        // Step 8: tv4 = A' * tv4
        tv4 = Fp.mul(A_PRIME, tv4);
        // Step 9: tv2 = tv3²
        tv2 = Fp.sqr(tv3);
        // Step 10: tv6 = tv4²
        bytes memory tv6 = Fp.sqr(tv4);
        // Step 11: tv5 = A' * tv6
        bytes memory tv5 = Fp.mul(A_PRIME, tv6);
        // Step 12: tv2 = tv2 + tv5
        tv2 = Fp.add(tv2, tv5);
        // Step 13: tv2 = tv2 * tv3
        tv2 = Fp.mul(tv2, tv3);
        // Step 14: tv6 = tv6 * tv4
        tv6 = Fp.mul(tv6, tv4);
        // Step 15: tv5 = B' * tv6
        tv5 = Fp.mul(B_PRIME, tv6);
        // Step 16: tv2 = tv2 + tv5
        tv2 = Fp.add(tv2, tv5);
        // Step 17: xN_candidate = tv1 * tv3
        xN = Fp.mul(tv1, tv3);
        // Step 18: sqrt_ratio(tv2, tv6)
        (bool is_gx1_square, bytes memory y1) = Fp.sqrtRatio(tv2, tv6, SQRT_MINUS_Z);
        // Step 19: y = tv1 * u
        y = Fp.mul(tv1, u);
        // Step 20: y = y * y1
        y = Fp.mul(y, y1);
        // Step 21: xN = CMOV(xN, tv3, is_gx1_square)
        xN = is_gx1_square ? tv3 : xN;
        // Step 22: y = CMOV(y, y1, is_gx1_square)
        y = is_gx1_square ? y1 : y;
        // Step 23-24: if sgn0(u) != sgn0(y), negate y
        if (Fp.sgn0(u) != Fp.sgn0(y)) {
            y = Fp.neg(y);
        }
        // Return projective: x' = xN / tv4 (don't invert)
        xD = tv4;
    }

    // ── Cofactor clearing on E1 (Jacobian input) ─────────────────────

    /// @dev Clear the G1 cofactor by multiplying by h_eff = 0xd201000000010001.
    ///      Input is already in Jacobian coordinates from projective isogeny.
    function _clearCofactorJac(bytes memory jX, bytes memory jY, bytes memory jZ)
        private
        pure
        returns (bytes memory, bytes memory)
    {
        // h_eff = 0xd201000000010001 (64 bits)
        uint256 scalar = 0xd201000000010001;

        // Convert Jacobian base point to affine for mixed additions
        bytes memory zInvBase = Fp.inv(jZ);
        bytes memory zInv2Base = Fp.sqr(zInvBase);
        bytes memory zInv3Base = Fp.mul(zInv2Base, zInvBase);
        bytes memory px = Fp.mul(jX, zInv2Base);
        bytes memory py = Fp.mul(jY, zInv3Base);

        // Start in Jacobian: (X, Y, Z) = (px, py, 1)
        bytes memory rX = px;
        bytes memory rY = py;
        bytes memory rZ = Fp.fromUint256(1);

        // Double-and-add from bit 62 down to 0 (bit 63 is MSB, already set as initial point)
        for (uint256 i = 63; i > 0;) {
            unchecked { --i; }
            (rX, rY, rZ) = _g1JacDouble(rX, rY, rZ);
            if ((scalar >> i) & 1 == 1) {
                // Mixed add: Jacobian + affine base point
                (rX, rY, rZ) = _g1JacAddMixed(rX, rY, rZ, px, py);
            }
        }

        // Convert back to affine: single inversion
        bytes memory zInv = Fp.inv(rZ);
        bytes memory zInv2 = Fp.sqr(zInv);
        bytes memory zInv3 = Fp.mul(zInv2, zInv);
        return (Fp.mul(rX, zInv2), Fp.mul(rY, zInv3));
    }

    /// @dev Jacobian point doubling on E1 (A=0): dbl-2009-l from hyperelliptic.org.
    ///      Cost: 1M + 5S + adds (no inversions).
    function _g1JacDouble(bytes memory X, bytes memory Y, bytes memory Z)
        private pure returns (bytes memory X3, bytes memory Y3, bytes memory Z3)
    {
        bytes memory A = Fp.sqr(X);
        bytes memory B = Fp.sqr(Y);
        bytes memory C = Fp.sqr(B);
        // D = 2*((X+B)^2 - A - C)
        bytes memory D = Fp.sub(Fp.sub(Fp.sqr(Fp.add(X, B)), A), C);
        D = Fp.add(D, D);
        // E = 3*A
        bytes memory E = Fp.add(A, Fp.add(A, A));
        bytes memory F = Fp.sqr(E);
        // X3 = F - 2*D
        X3 = Fp.sub(F, Fp.add(D, D));
        // Y3 = E*(D - X3) - 8*C
        bytes memory C8 = Fp.add(C, C);
        C8 = Fp.add(C8, C8);
        C8 = Fp.add(C8, C8);
        Y3 = Fp.sub(Fp.mul(E, Fp.sub(D, X3)), C8);
        // Z3 = 2*Y*Z
        Z3 = Fp.mul(Fp.add(Y, Y), Z);
    }

    /// @dev Mixed Jacobian + affine addition on E1: madd-2007-bl.
    ///      (X1:Y1:Z1) + (x2, y2) where Z2=1.
    ///      Cost: 7M + 4S + adds (no inversions).
    function _g1JacAddMixed(
        bytes memory X1, bytes memory Y1, bytes memory Z1,
        bytes memory x2, bytes memory y2
    ) private pure returns (bytes memory X3, bytes memory Y3, bytes memory Z3) {
        bytes memory Z1Z1 = Fp.sqr(Z1);
        // U2 = x2 * Z1^2
        bytes memory U2 = Fp.mul(x2, Z1Z1);
        // S2 = y2 * Z1^3
        bytes memory S2 = Fp.mul(y2, Fp.mul(Z1, Z1Z1));
        // H = U2 - X1
        bytes memory H = Fp.sub(U2, X1);
        bytes memory HH = Fp.sqr(H);
        bytes memory I = Fp.add(HH, HH);
        I = Fp.add(I, I); // I = 4*H^2
        bytes memory J = Fp.mul(H, I);
        // R = 2*(S2 - Y1)
        bytes memory R = Fp.add(Fp.sub(S2, Y1), Fp.sub(S2, Y1));
        bytes memory V = Fp.mul(X1, I);
        // X3 = R^2 - J - 2*V
        X3 = Fp.sub(Fp.sub(Fp.sqr(R), J), Fp.add(V, V));
        // Y3 = R*(V - X3) - 2*Y1*J
        Y3 = Fp.sub(Fp.mul(R, Fp.sub(V, X3)), Fp.mul(Fp.add(Y1, Y1), J));
        // Z3 = (Z1 + H)^2 - Z1Z1 - HH
        Z3 = Fp.sub(Fp.sub(Fp.sqr(Fp.add(Z1, H)), Z1Z1), HH);
    }

    // ── 11-Isogeny from E'1 to E1 (projective) ─────────────────────

    /// @dev Evaluates 11-isogeny in homogeneous form and outputs Jacobian point.
    ///      Input: x' = N/D (projective), y' (affine on E'1).
    ///      Output: (X_j, Y_j, Z_j) Jacobian on E1.
    function _iso11Projective(bytes memory N, bytes memory D, bytes memory yp)
        private
        pure
        returns (bytes memory jX, bytes memory jY, bytes memory jZ)
    {
        // Evaluate all 4 polynomials in homogeneous form
        (bytes memory xNumH, ) = _evalPolyHom(N, D, _xNumCoeffs());
        (bytes memory xDenH, ) = _evalPolyMonicHom(N, D, _xDenCoeffs());
        (bytes memory yNumH, ) = _evalPolyHom(N, D, _yNumCoeffs());
        (bytes memory yDenH, ) = _evalPolyMonicHom(N, D, _yDenCoeffs());

        // The isogeny output in projective coordinates:
        // x_E = xNumH / (xDenH * D)
        // y_E = yp * yNumH / yDenH
        //
        // As projective (X:Y:Z) with x=X/Z, y=Y/Z:
        // X = xNumH * yDenH
        // Y = yp * yNumH * xDenH * D
        // Z = xDenH * D * yDenH
        //
        // Convert to Jacobian (X_j:Y_j:Z_j) with x=X_j/Z_j^2, y=Y_j/Z_j^3:
        // Z_j = Z = xDenH * D * yDenH
        // X_j = X * Z = xNumH * yDenH * Z_j
        // Y_j = Y * Z^2 = yp * yNumH * xDenH * D * Z_j^2

        jZ = Fp.mul(Fp.mul(xDenH, D), yDenH);
        jX = Fp.mul(Fp.mul(xNumH, yDenH), jZ);
        bytes memory jZ2 = Fp.sqr(jZ);
        jY = Fp.mul(Fp.mul(Fp.mul(yp, yNumH), Fp.mul(xDenH, D)), jZ2);
    }

    // ── Homogeneous polynomial evaluation ─────────────────────────

    /// @dev Evaluate polynomial P(N/D) in homogeneous form.
    ///      Returns (num, den) such that P(N/D) = num/den, where den = D^n.
    ///      coeffs are stored high-degree-first: [c_n, c_{n-1}, ..., c_0]
    ///      Uses homogeneous Horner: acc = c_n; for i: D_pow *= D; acc = acc*N + c_i*D_pow
    function _evalPolyHom(bytes memory N, bytes memory D, bytes[] memory coeffs)
        private
        pure
        returns (bytes memory num, bytes memory den)
    {
        num = coeffs[0];
        den = Fp.fromUint256(1);
        for (uint256 i = 1; i < coeffs.length; i++) {
            den = Fp.mul(den, D);
            num = Fp.add(Fp.mul(num, N), Fp.mul(coeffs[i], den));
        }
    }

    /// @dev Evaluate monic polynomial (leading coeff = 1) in homogeneous form.
    ///      Returns (num, den) such that P(N/D) = num/den, where den = D^n.
    ///      coeffs are stored high-degree-first (without the leading 1): [c_{n-1}, ..., c_0]
    function _evalPolyMonicHom(bytes memory N, bytes memory D, bytes[] memory coeffs)
        private
        pure
        returns (bytes memory num, bytes memory den)
    {
        num = Fp.fromUint256(1);
        den = Fp.fromUint256(1);
        for (uint256 i = 0; i < coeffs.length; i++) {
            den = Fp.mul(den, D);
            num = Fp.add(Fp.mul(num, N), Fp.mul(coeffs[i], den));
        }
    }

    // ── Isogeny coefficient arrays ──────────────────────────────────

    function _xNumCoeffs() private pure returns (bytes[] memory c) {
        c = new bytes[](12);
        c[0]  = hex"06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229";
        c[1]  = hex"10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b";
        c[2]  = hex"169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e";
        c[3]  = hex"080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317";
        c[4]  = hex"17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e";
        c[5]  = hex"0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84";
        c[6]  = hex"1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983";
        c[7]  = hex"0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9";
        c[8]  = hex"1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861";
        c[9]  = hex"0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0";
        c[10] = hex"17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb";
        c[11] = hex"11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7";
    }

    function _xDenCoeffs() private pure returns (bytes[] memory c) {
        c = new bytes[](10);
        c[0] = hex"095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a";
        c[1] = hex"0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641";
        c[2] = hex"14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e";
        c[3] = hex"0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a";
        c[4] = hex"0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5";
        c[5] = hex"13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e";
        c[6] = hex"03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8";
        c[7] = hex"0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19";
        c[8] = hex"12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff";
        c[9] = hex"08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c";
    }

    function _yNumCoeffs() private pure returns (bytes[] memory c) {
        c = new bytes[](16);
        c[0]  = hex"15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604";
        c[1]  = hex"05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b";
        c[2]  = hex"0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133";
        c[3]  = hex"0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8";
        c[4]  = hex"18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e";
        c[5]  = hex"19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132";
        c[6]  = hex"0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30";
        c[7]  = hex"09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587";
        c[8]  = hex"0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29";
        c[9]  = hex"04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2";
        c[10] = hex"16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0";
        c[11] = hex"08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb";
        c[12] = hex"01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb";
        c[13] = hex"00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6";
        c[14] = hex"134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696";
        c[15] = hex"090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33";
    }

    function _yDenCoeffs() private pure returns (bytes[] memory c) {
        c = new bytes[](15);
        c[0]  = hex"0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f";
        c[1]  = hex"02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7";
        c[2]  = hex"0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc";
        c[3]  = hex"0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092";
        c[4]  = hex"04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8";
        c[5]  = hex"167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55";
        c[6]  = hex"1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a";
        c[7]  = hex"16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9";
        c[8]  = hex"166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c";
        c[9]  = hex"08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac";
        c[10] = hex"0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d";
        c[11] = hex"16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416";
        c[12] = hex"058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2";
        c[13] = hex"1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d";
        c[14] = hex"16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1";
    }
}
