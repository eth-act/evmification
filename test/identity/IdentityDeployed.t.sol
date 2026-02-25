// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {IdentityDeployed} from "../../src/identity/IdentityDeployed.sol";

/// @dev Tests that IdentityDeployed is indistinguishable from the 0x04 precompile.
contract IdentityDeployedTest is Test {
    address deployed;

    function setUp() public {
        deployed = address(new IdentityDeployed());
    }

    function _callPrecompile(bytes memory data) internal view returns (bool, bytes memory) {
        return address(0x04).staticcall(data);
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

    function test_identical_hello() public view {
        (bool okPre, bytes memory outPre) = _callPrecompile("hello");
        (bool okDep, bytes memory outDep) = _callDeployed("hello");
        assertTrue(okPre);
        assertTrue(okDep);
        assertEq(outDep, outPre);
    }

    function test_identical_256bytes() public view {
        bytes memory data = new bytes(256);
        for (uint256 i = 0; i < 256; i++) data[i] = bytes1(uint8(i));
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
