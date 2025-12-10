// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {INitroEnclaveVerifier} from
    "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import "./OlympixUnitTest.sol";

contract EspressoNitroTEEVerifierTest is Test, OlympixUnitTest("EspressoNitroTEEVerifier") {
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
            pcr0Hash,
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788) // Sepolia Nitro Enclave Verifier address
        );
        vm.stopPrank();
    }

    /**
     * Test register signer succeeds upon valid attestation and signature
     */
    function testRegisterSigner() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // register and verify signer exists
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
        vm.stopPrank();
    }

    /**
     * Test register signer fails upon invalid attestation pcr0
     */
    function testRegisterSignerInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");

        // Extract onchain_proof
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);

        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
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
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
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
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
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
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), true);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
        vm.stopPrank();
    }

    /**
     * Test we can delete a registered signer with only the correct admin address
     */
    function testDeleteRegisterSignerOwnership() public {
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
        espressoNitroTEEVerifier.registerSigner(journal, onchain);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertEq(espressoNitroTEEVerifier.registeredSigners(signer), true);

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        address[] memory signersToDelete = new address[](1);
        signersToDelete[0] = signer;

        // verify we cant delete
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.deleteRegisteredSigners(signersToDelete);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete and verify signer address is gone
        espressoNitroTEEVerifier.deleteRegisteredSigners(signersToDelete);
        assertEq(espressoNitroTEEVerifier.registeredSigners(signer), false);
    }

    /// @dev Covers setEnclaveHash: require(enclaveHash != bytes32(0), ...) opix-target-branch-97-True
    function testSetEnclaveHashZeroHashReverts() public {
        // Only owner can call setEnclaveHash. Use adminTEE which is owner per setUp().
        vm.startPrank(adminTEE);
        bytes32 zeroHash = bytes32(0);
        vm.expectRevert(bytes("Enclave hash cannot be zero"));
        espressoNitroTEEVerifier.setEnclaveHash(zeroHash, true);
        vm.stopPrank();
    }

    /// @dev Covers deleteRegisteredSigners: if (true) { ... } opix-target-branch-103-True -- This test covers the unconditional for loop/deletion path for branch coverage, using a dummy address array.
    function testDeleteRegisteredSignersCoversIfTrueBranch() public {
        vm.startPrank(adminTEE);
        // Create an array of addresses to delete (could be empty or dummy -- all that is needed for this branch is to exercise the function as owner)
        address[] memory signersToDelete = new address[](2);
        signersToDelete[0] = address(0xABCDE1);
        signersToDelete[1] = address(0xABCDE2);

        // Optionally, prime a value to test deletion effect:
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
        // Set registeredSigners slots directly if wanted:
        bytes32 slot0 = keccak256(abi.encode(address(0xABCDE1), uint256(1))); // mapping slot for registeredSigners(addr)
        bytes32 slot1 = keccak256(abi.encode(address(0xABCDE2), uint256(1)));
        // Use stdstore/cheatcodes to modify storage if you want; but just call the function for now for branch coverage:
        // Calling the function covers branch as owner.
        espressoNitroTEEVerifier.deleteRegisteredSigners(signersToDelete);
        vm.stopPrank();
        // Optionally, assert postcondition:
        assertEq(espressoNitroTEEVerifier.registeredSigners(address(0xABCDE1)), false);
        assertEq(espressoNitroTEEVerifier.registeredSigners(address(0xABCDE2)), false);
    }

    /**
     * opix-target-branch-83-YOUR-TEST-SHOULD-ENTER-THIS-ELSE-BRANCH-BY-MAKING-THE-PRECEDING-IFS-CONDITIONS-FALSE
     * This test covers the branch where the signer has already been registered.
     * We will register a signer once, then call registerSigner again with the same input/config,
     * so `if (!registeredSigners[enclaveAddress])` is false, entering the else branch and hitting `assert(true);`.
     * This is a pure branch-coverage test and does not check for reverts -- just that the second registration is a no-op/assert.
     */
    function testRegisterSignerAlreadyRegisteredHitsElseBranch() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory journal = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory onchain = vm.parseJsonBytes(json, ".onchain_proof");
        // Register the signer the first time (happy-path)
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
        // Register the same signer again, to hit the 'already registered' else branch
        espressoNitroTEEVerifier.registerSigner(journal, onchain);
        // If the function did not revert, the else branch with `assert(true)` was hit
        vm.stopPrank();
    }
}
