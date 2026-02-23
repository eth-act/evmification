// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ModexpPrecompile} from "../../src/modexp/ModexpPrecompile.sol";
import {ModexpBarrett} from "../../src/modexp/ModexpBarrett.sol";
import {Modexp} from "../../src/modexp/Modexp.sol";

contract BarrettVectorRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return ModexpBarrett.modexp(base, exponent, modulus);
    }
}

contract ModexpVectorRunner {
    function run(bytes calldata base, bytes calldata exponent, bytes calldata modulus)
        external view returns (bytes memory)
    {
        return Modexp.modexp(base, exponent, modulus);
    }
}

contract ModexpVectorsTest is Test {
    struct Vector {
        string name;
        bytes base;
        bytes exponent;
        bytes modulus;
        bytes expected;
    }

    BarrettVectorRunner barrettRunner;
    ModexpVectorRunner modexpRunner;

    function setUp() public {
        barrettRunner = new BarrettVectorRunner();
        modexpRunner = new ModexpVectorRunner();
    }

    function _loadVectors() internal view returns (Vector[] memory vecs) {
        string memory json = vm.readFile("test/modexp/fixtures/modexp_vectors.json");
        uint256 n = vm.parseJsonUint(json, "$.count");
        vecs = new Vector[](n);
        for (uint256 i; i < n; ++i) {
            string memory p = string.concat("$.vectors[", vm.toString(i), "]");
            vecs[i].name = vm.parseJsonString(json, string.concat(p, ".name"));
            vecs[i].base = vm.parseJsonBytes(json, string.concat(p, ".base"));
            vecs[i].exponent = vm.parseJsonBytes(json, string.concat(p, ".exponent"));
            vecs[i].modulus = vm.parseJsonBytes(json, string.concat(p, ".modulus"));
            vecs[i].expected = vm.parseJsonBytes(json, string.concat(p, ".expected"));
        }
    }

    function test_all_vectors() public view {
        Vector[] memory vecs = _loadVectors();
        for (uint256 i; i < vecs.length; ++i) {
            bytes memory result = ModexpPrecompile.modexp(vecs[i].base, vecs[i].exponent, vecs[i].modulus);
            assertEq(result, vecs[i].expected, vecs[i].name);
        }
    }

    function test_barrett_all_vectors() public view {
        Vector[] memory vecs = _loadVectors();
        for (uint256 i; i < vecs.length; ++i) {
            bytes memory result = barrettRunner.run(vecs[i].base, vecs[i].exponent, vecs[i].modulus);
            assertEq(result, vecs[i].expected, vecs[i].name);
        }
    }

    function test_modexp_all_vectors() public view {
        Vector[] memory vecs = _loadVectors();
        for (uint256 i; i < vecs.length; ++i) {
            bytes memory result = modexpRunner.run(vecs[i].base, vecs[i].exponent, vecs[i].modulus);
            assertEq(result, vecs[i].expected, vecs[i].name);
        }
    }
}
