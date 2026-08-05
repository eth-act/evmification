// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2 as console} from "forge-std/Test.sol";
import {Ripemd160Deployed} from "../../src/ripemd160/Ripemd160Deployed.sol";

/// @notice Head-to-head cost of the deployed EVM implementation vs the native
///         precompile at 0x03. Both are reached by staticcall with the identical
///         raw-bytes calling convention, so the same call overhead sits on each
///         side and cancels out of the difference.
contract Ripemd160ProfileTest is Test {
    Ripemd160Deployed evmImpl;
    address constant PRECOMPILE = address(0x03);

    function setUp() public {
        evmImpl = new Ripemd160Deployed();
        // Warm both accounts so we measure execution, not the cold-access charge.
        _call(address(evmImpl), hex"00");
        _call(PRECOMPILE, hex"00");
    }

    function _call(address target, bytes memory data) internal view returns (bytes32 out) {
        (bool ok, bytes memory ret) = target.staticcall(data);
        require(ok && ret.length == 32, "call failed");
        out = abi.decode(ret, (bytes32));
    }

    function _g(address target, bytes memory data) internal view returns (uint256) {
        uint256 s = gasleft();
        _call(target, data);
        return s - gasleft();
    }

    /// Deterministic input of `n` bytes.
    function _input(uint256 n) internal pure returns (bytes memory data) {
        data = new bytes(n);
        for (uint256 i = 0; i < n; i++) data[i] = bytes1(uint8(i));
    }

    function _profile(uint256 size) internal view {
        bytes memory data = _input(size);

        uint256 evmGas = _g(address(evmImpl), data);
        uint256 preGas = _g(PRECOMPILE, data);

        assertEq(_call(address(evmImpl), data), _call(PRECOMPILE, data), "digest mismatch");
        assertEq(_call(PRECOMPILE, data), bytes32(ripemd160(data)) >> 96, "vs builtin mismatch");

        console.log("--- input bytes", size);
        console.log("  blocks       ", (size + 9 + 63) / 64); // ceil((len + 9) / 64)
        console.log("  evm          ", evmGas);
        console.log("  precompile   ", preGas);
        console.log("  ratio x100   ", (evmGas * 100) / preGas);
    }

    // 55 is the largest single-block message: padding appends 0x80 + an 8-byte
    // length, so 56..64 spills into a second block and doubles the EVM cost.
    function test_profile_0() public view { _profile(0); }
    function test_profile_5() public view { _profile(5); }
    function test_profile_32() public view { _profile(32); }
    function test_profile_55() public view { _profile(55); }
    function test_profile_64() public view { _profile(64); }
    function test_profile_256() public view { _profile(256); }
    function test_profile_1024() public view { _profile(1024); }

    /// Strips fixed call overhead from both sides to expose the rate that the
    /// end-to-end ratio converges on as input grows.
    ///
    /// The two sides bill in different units and must be measured in their own:
    /// the EVM implementation costs per 64-byte compression block, the
    /// precompile per 32-byte input word. Those do not scale together (32 bytes
    /// is 1 block but 1 word; 1024 bytes is 17 blocks but 32 words), so the
    /// deltas are divided by their respective counts and only then compared.
    function test_marginal_per_block() public view {
        bytes memory small = _input(32); // 1 block, 1 word
        bytes memory large = _input(1024); // 17 blocks, 32 words

        uint256 evmPerBlock = (_g(address(evmImpl), large) - _g(address(evmImpl), small)) / 16;
        uint256 prePerWord = (_g(PRECOMPILE, large) - _g(PRECOMPILE, small)) / 31;
        uint256 prePerBlock = prePerWord * 2; // a 64-byte block is 2 input words

        console.log("--- marginal cost");
        console.log("  evm  per block", evmPerBlock);
        console.log("  pre  per word ", prePerWord);
        console.log("  pre  per block", prePerBlock);
        console.log("  ratio         ", evmPerBlock / prePerBlock);

        // Precompile is specified at 120 gas per input word. Allow a small
        // tolerance: the measured delta also carries the caller-side memory
        // expansion for the return buffer, which lands above a 1024-byte input
        // and a 32-byte one at different offsets.
        assertApproxEqAbs(prePerWord, 120, 2, "precompile off its 120/word rate");
        assertGt(evmPerBlock, 100 * prePerBlock, "EVM impl unexpectedly close to precompile");
    }
}
