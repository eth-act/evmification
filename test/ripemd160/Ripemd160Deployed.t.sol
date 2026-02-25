// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Ripemd160Deployed} from "../../src/ripemd160/Ripemd160Deployed.sol";

/// @dev Tests that Ripemd160Deployed is indistinguishable from the 0x03 precompile.
contract Ripemd160DeployedTest is Test {
    address deployed;

    function setUp() public {
        deployed = address(new Ripemd160Deployed());
    }

    function _callPrecompile(bytes memory data) internal view returns (bool, bytes memory) {
        return address(0x03).staticcall(data);
    }

    function _callDeployed(bytes memory data) internal view returns (bool, bytes memory) {
        return deployed.staticcall(data);
    }

    function test_identical_empty() public view {
        (bool okPre, bytes memory outPre) = _callPrecompile("");
        (bool okDep, bytes memory outDep) = _callDeployed("");
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_abc() public view {
        (bool okPre, bytes memory outPre) = _callPrecompile("abc");
        (bool okDep, bytes memory outDep) = _callDeployed("abc");
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_multiblock() public view {
        bytes memory data = new bytes(80);
        for (uint256 i = 0; i < 80; i++) data[i] = bytes1(uint8(i));
        (bool okPre, bytes memory outPre) = _callPrecompile(data);
        (bool okDep, bytes memory outDep) = _callDeployed(data);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function testFuzz_identical_to_precompile(bytes calldata data) public view {
        (bool okPre, bytes memory outPre) = _callPrecompile(data);
        (bool okDep, bytes memory outDep) = _callDeployed(data);
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre, "deployed != precompile");
    }
}
