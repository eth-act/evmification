// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {RSAVerify} from "../src/RSAVerify.sol";
import {RSAVerifyMontgomery} from "../src/RSAVerifyMontgomery.sol";
import {RSAVerifyMontgomeryReadable} from "../src/RSAVerifyMontgomeryReadable.sol";

/// @notice Thin wrapper to make library calls external for gas measurement.
contract RSAVerifyCaller {
    function verify(
        bytes calldata modulus,
        bytes calldata exponent,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        return RSAVerify.verify(modulus, exponent, message, signature);
    }
}

/// @notice Thin wrapper for Montgomery library calls for gas measurement.
contract RSAVerifyMontgomeryCaller {
    function verify(
        bytes calldata modulus,
        bytes calldata exponent,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        return RSAVerifyMontgomery.verify(modulus, exponent, message, signature);
    }
}

/// @notice Thin wrapper for readable Montgomery library calls for gas measurement.
contract RSAVerifyMontgomeryReadableCaller {
    function verify(
        bytes calldata modulus,
        bytes calldata exponent,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        return RSAVerifyMontgomeryReadable.verify(modulus, exponent, message, signature);
    }
}

contract RSABenchmarkTest is Test {
    RSAVerifyCaller verifier;
    RSAVerifyMontgomeryCaller montgomeryVerifier;
    RSAVerifyMontgomeryReadableCaller readableVerifier;

    bytes constant MSG = hex"68656c6c6f"; // "hello"
    bytes constant E = hex"010001"; // 65537

    // RSA-2048
    bytes constant N_2048 = hex"92dba85e8fea9ce6b77f0c86f812b77b4e3a58f66caa6913007464514508515c299931d817effc6b56e269183d607ce17a853ca59f97f55cec22140666a3cac78cd7b7f4bd40fe57c17b37bb204db831b3bad5594c4f8055957a88fe3a234d768913c582257dd848b8bb300f851ea508172884e6a5f7fba45cad63b3a99c440cb3af73551ecc8ddf66d59a654b7c8b1dab13cf970ab0ba65dcb3101db20bd7f7c39328154eabeb832729c63f92de42395aea71c0666c714af5f588f1e2197ea2eef1785a825e2b88d760bfa89486eabc4cdeaec8d0e4e2919b719e31e0c2653517f6306b4816f1c2c76fc8403d8445f2de820bfe30f465ed6c22f0fff859ea51";
    bytes constant SIG_2048 = hex"523a9711d648add17499657af3f3ed3afe5f7ca1a337bac9cf8d7567b94bbb82f32a1f2d97f53bc37a898ddcc1d6f1c1b335cd0e6d3c81fbaa743f88c5f2142502915f2b62f65fe57287b3fc0849ef14a3cd13f1fb55a899f0ef45a136ed158a5d5d68e3fcb35a040f07c0ce0d98b178e30d32e8f3ad85c3c04999668e13ab9dd5aec461d86107c3583b386f889686603d166f7428d7372e28bbf6a2cef91ba4a3d1110ed0e9ccb6b3903b9efd43587877955ad14caebd4433e35d2f2a250c20dee230d160b2dcdac88ca5f48576a32dbe06824dbcace7e82ba1a357d390653f4a150a4b651c90a88b6127b0af401db1718e533d4eb0837764733eed03ad3529";

    // RSA-4096
    bytes constant N_4096 = hex"ddfed2f4842c0139cf34b66c8930691bbd712677e446228ac1e95680c839442f1ad5c814f6e26966dd3103f03d2ee39f84abcd821abc1825ac03678a5a94c2d5475f64c176b1cb9b853083414fc6959644f70d0c546a6ac686dedf656297e46ff183e3b3b2e2f70c00a32515130a9467b5142edb8a385fb5633e76d91ba10956a3ab4088254775518b85dc938c5cd7a77773c730ca92f3c11e7acf39bac882b8158691a271fe9d591949cbd8b4ad230693a70162b9314d102b6640f65e686e3886367403d54da2f7fa9a2b0c3c111a05f9528ebe1744fd6a0a94b2cb3d265d9e8a0362bf05a8f74de5eed9d7eb49a0297cbdf32296e98de37e688272c8f1e2738fe548eb9a4dc1fda9aff46fe3d9c789190a884c950c277de57512b9ed6af7e8390aa1a14200c8d59bd441a905c8e7c04428af3f5971690010f1c913f670e9d816c21b6577fc82e235b47bcc1de9165dff5b4d1d13d55b92e81dab6936e34ddb2ddeff4258b459eaaf40557ef7b48471e4bebb7d2f2f05c4baf505ea622dcad4803b66a2dd7ec48d9f00ce683752e1ca21d57bf6433f7ada03d6c7cd706eb7471c09b46f21803c2abbedc77f04b4ad8f3a4ee82e072dc6e5dd4b423e492952e93c1cc38b1ebba2f88049c2cd7319c77b5edd64e3a7c24612f6cd6cdab7db863d3fdc4eafa0d674fe2469396f38f91b4b37b544e690db3153849d561c20e3f0e7";
    bytes constant SIG_4096 = hex"c0173dbfcad4873a603b1b4f1d69d2edaac55618cd9066f6ef19e81d77c27979ee933a2cca6df03cde4f44ad0bf22d35f7162b15cab74263460770084da465e6524cb169a290a66bf9f8d0067c528f090e82b7c23bdd9c2f5520e306f5203f4efd9d106918209b598b8e5259ae755a96bb8af694a3385cb1926e098f121304e3e95d8b4c6909ed92b70724122d0a03856f56ba35e6fa9735f3e63a78abe596d03d07e168e433dd7426405718696c7921f7b3cb2b6cd54cfc3e6c6923e9920f70d6113877d515d7a3b1f2148f54bf4b54638595c02b808bf2c8513d7a859dacb5efdc53a8acb77fab0f8fe694d5ce6b45c392143a073b5f546d00c7d37817d7e1c48dcb15162510178158026034b3544699a5f9ee9f24fdfa3b617d0991a5ad8a25a3b63e291b5f6cbf289e4b0fd49d38630e095778ba3b63f2134e06019ba52587c71c6f0ee455ef28edeabd7bc51223692a42d98fb7764f888f3c9df4299e394c8c0c6e8923321fa28da7bf6c3292a31d83f003dc3dce3efee0434510bdb9fafa56ada2c893c4113914e62ae9d914cb7b81554fb859adb969be05dc271e4d8d6d750bd2e0a9e4687aa524d6ec4f464915cc55b99c991e681092d7411296b9305d1dd5b5c39a8bd8dca572e4412ef7495a71f6ea64a0c7b918cba3444ebcfa5ced91d7ca04f4cb162652ce19a77f2893fae01d4caf650ac1b7650fc653124eaf";

    function setUp() public {
        verifier = new RSAVerifyCaller();
        montgomeryVerifier = new RSAVerifyMontgomeryCaller();
        readableVerifier = new RSAVerifyMontgomeryReadableCaller();
    }

    function test_rsa2048_verify() public view {
        bool valid = verifier.verify(N_2048, E, MSG, SIG_2048);
        require(valid, "RSA-2048 verification failed");
    }

    function test_rsa4096_verify() public view {
        bool valid = verifier.verify(N_4096, E, MSG, SIG_4096);
        require(valid, "RSA-4096 verification failed");
    }

    function test_rsa2048_verify_montgomery() public view {
        bool valid = montgomeryVerifier.verify(N_2048, E, MSG, SIG_2048);
        require(valid, "Montgomery RSA-2048 verification failed");
    }

    function test_rsa4096_verify_montgomery() public view {
        bool valid = montgomeryVerifier.verify(N_4096, E, MSG, SIG_4096);
        require(valid, "Montgomery RSA-4096 verification failed");
    }

    function test_rsa2048_verify_readable() public view {
        bool valid = readableVerifier.verify(N_2048, E, MSG, SIG_2048);
        require(valid, "Readable RSA-2048 verification failed");
    }

    function test_rsa4096_verify_readable() public view {
        bool valid = readableVerifier.verify(N_4096, E, MSG, SIG_4096);
        require(valid, "Readable RSA-4096 verification failed");
    }
}
