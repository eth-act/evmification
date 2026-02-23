// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {Blake2fPrecompile} from "../../src/blake2f/Blake2fPrecompile.sol";
import {Blake2f} from "../../src/blake2f/Blake2f.sol";

contract Blake2fPureVectorRunner {
    function run(bytes calldata input) external pure returns (bytes memory) {
        return Blake2f.compress(input);
    }
}

contract Blake2fVectorsTest is Test {
    struct Vector {
        string name;
        bytes input;
        bytes expected;
    }

    Blake2fPureVectorRunner pureRunner;

    function setUp() public {
        pureRunner = new Blake2fPureVectorRunner();
    }

    function _loadVectors() internal view returns (Vector[] memory vecs) {
        string memory json = vm.readFile("test/blake2f/fixtures/blake2f_vectors.json");
        uint256 n = vm.parseJsonUint(json, "$.count");
        vecs = new Vector[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat("$.vectors[", vm.toString(i), "]");
            vecs[i].name = vm.parseJsonString(json, string.concat(p, ".name"));
            vecs[i].input = vm.parseJsonBytes(json, string.concat(p, ".input"));
            vecs[i].expected = vm.parseJsonBytes(json, string.concat(p, ".expected"));
        }
    }

    function test_precompile_all_vectors() public view {
        Vector[] memory vecs = _loadVectors();
        for (uint256 i; i < vecs.length; ++i) {
            bytes memory result = Blake2fPrecompile.compress(vecs[i].input);
            assertEq(result, vecs[i].expected, vecs[i].name);
        }
    }

    function test_pure_all_vectors() public view {
        Vector[] memory vecs = _loadVectors();
        for (uint256 i; i < vecs.length; ++i) {
            bytes memory result = pureRunner.run(vecs[i].input);
            assertEq(result, vecs[i].expected, vecs[i].name);
        }
    }
}
