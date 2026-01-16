// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

contract EspressoNitroTEEVerifierTest is Test {
    address proxyAdmin = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788) // Sepolia Nitro Enclave Verifier address
        );
        // Register the enclave hash used in bundled proof fixtures
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        // Register the enclave hash for caff node used in bundled proof fixtures
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
        vm.stopPrank();
    }

    /**
     * Test register signer succeeds upon valid attestation and signature
     */
    function testRegisterBatchPoster() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerBatchPoster(journal, onchain);
        vm.stopPrank();
    }

    /**
     *     Test register caff node succeeds upon valid attestation and signature
     */
    function testRegisterCaffNode() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerCaffNode(journal, onchain);
        vm.stopPrank();
    }

    /**
     * Test register signer fails upon invalid attestation pcr0
     */
    function testRegisterBatchPosterInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), false);

        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoNitroTEEVerifier.registerBatchPoster(journal, onchain);
        vm.stopPrank();
    }

    /**
     * Test register caff node fails upon invalid attestation pcr0
     */
    function testRegisterCaffNodeInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.CaffNode);
        assertEq(espressoNitroTEEVerifier.registeredCaffNodeEnclaveHashes(pcr0Hash), false);
        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoNitroTEEVerifier.registerCaffNode(journal, onchain);
        vm.stopPrank();
    }

    /**
     * Test invalid proof reverts the transaction
     */
    function testInvalidProof() public {
        vm.startPrank(adminTEE);
        string memory proofPath = "/test/configs/invalid_proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        vm.expectRevert();
        espressoNitroTEEVerifier.registerBatchPoster(journal, onchain);

        vm.expectRevert();
        espressoNitroTEEVerifier.registerCaffNode(journal, onchain);
        vm.stopPrank();
    }

    /*
     * Test if expired proof reverts
     */
    function testExpiredProof() public {
        vm.startPrank(adminTEE);
        vm.warp(1_433_353_188);
        string memory proofPath = "/test/configs/expired_proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        vm.expectRevert();
        espressoNitroTEEVerifier.registerBatchPoster(journal, onchain);

        vm.expectRevert();
        espressoNitroTEEVerifier.registerCaffNode(journal, onchain);
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
    function testNitroOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoNitroTEEVerifier.owner()), adminTEE);
        espressoNitroTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoNitroTEEVerifier.acceptOwnership();
        assertEq(address(espressoNitroTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    // Test transfer Ownership failure
    function testNitroOwnershipTransferFailure() public {
        vm.startPrank(fakeAddress);
        assertEq(address(espressoNitroTEEVerifier.owner()), adminTEE);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        espressoNitroTEEVerifier.transferOwnership(address(150));
    }

    // Test setting Enclave hash for owner and non-owner
    function testSetNitroEnclaveHash() public {
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), true);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        vm.stopPrank();

        // do the same tests for CaffNode
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
        assertEq(espressoNitroTEEVerifier.registeredCaffNodeEnclaveHashes(pcr0Hash), true);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.CaffNode);
        assertEq(espressoNitroTEEVerifier.registeredCaffNodeEnclaveHashes(pcr0Hash), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.CaffNode);
        vm.stopPrank();
    }

    /**
     * Test we can delete a registered signer with only the correct admin address
     */
    function testDeleteRegisterBatchPosterOwnership() public {
        // register signer
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerBatchPoster(journal, onchain);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertEq(espressoNitroTEEVerifier.registeredBatchPosters(signer), true);

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        address[] memory signersToDelete = new address[](1);
        signersToDelete[0] = signer;

        // verify we cant delete
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.deleteRegisteredBatchPosters(signersToDelete);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete and verify signer address is gone
        espressoNitroTEEVerifier.deleteRegisteredBatchPosters(signersToDelete);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosters(signer), false);
    }

    // Test we can delete a registered caff node with only the correct admin address
    function testDeleteRegisterCaffNodeOwnership() public {
        // register signer
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerCaffNode(journal, onchain);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertEq(espressoNitroTEEVerifier.registeredCaffNodes(signer), true);

        // delete and verify signer address is gone
        address[] memory signersToDelete = new address[](1);
        signersToDelete[0] = signer;
        espressoNitroTEEVerifier.deleteRegisteredCaffNodes(signersToDelete);
        assertEq(espressoNitroTEEVerifier.registeredCaffNodes(signer), false);
    }

    // Test setting Nitro Enclave Verifier address for owner and non-owner
    function testSetNitroEnclaveVerifierAddress() public {
        vm.startPrank(adminTEE);
        address newVerifierAddress = 0x1234567890123456789012345678901234567890;
        espressoNitroTEEVerifier.setNitroEnclaveVerifier(newVerifierAddress);
        vm.stopPrank();
        // Check that only owner can set the address
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setNitroEnclaveVerifier(newVerifierAddress);
        vm.stopPrank();
    }
}
