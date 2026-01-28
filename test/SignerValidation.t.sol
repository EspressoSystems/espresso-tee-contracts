// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Tests for isSignerValid() - Automatic Zombie Prevention
 * @notice Verifies that deleting a hash automatically invalidates its signers
 */
contract SignerValidationTest is Test {
    address proxyAdminOwner = address(140);
    address adminTEE = address(141);
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );

        EspressoNitroTEEVerifier impl = new EspressoNitroTEEVerifier();
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(impl), proxyAdminOwner, "");
        espressoNitroTEEVerifier = EspressoNitroTEEVerifier(address(proxy));

        vm.prank(adminTEE);
        espressoNitroTEEVerifier.initialize(
            adminTEE, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );

        vm.prank(adminTEE);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
    }

    /**
     * @dev Test: isSignerValid returns true for valid signer with valid hash
     */
    function test_IsSignerValid_ValidSigner() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);

        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;

        // Signer should be valid
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        vm.stopPrank();
    }

    /**
     * @dev Test: isSignerValid returns false after hash deletion (automatic revocation!)
     */
    function test_IsSignerValid_AfterHashDeletion() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);

        // Register signer
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;

        // Before deletion - signer should be valid
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        // Delete the hash
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = pcr0Hash;
        espressoNitroTEEVerifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // After deletion - signer is NOT valid (automatic revocation!)
        // Note: Signer remains in internal mapping but isSignerValid() returns false
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        vm.stopPrank();
    }

    /**
     * @dev Test: Prevents zombie signer attack
     */
    function test_PreventsZombieSigners() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);

        // Register signer with vulnerable hash
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;

        // Signer is valid
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        // Vulnerability discovered! Delete hash
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = pcr0Hash;
        espressoNitroTEEVerifier.deleteEnclaveHashes(hashes, ServiceType.BatchPoster);

        // Signer is now AUTOMATICALLY invalid (no zombies!)
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        vm.stopPrank();
    }

    /**
     * @dev Test: isSignerValid returns false for unregistered signer
     */
    function test_IsSignerValid_UnregisteredSigner() public view {
        address randomSigner = address(0x999);
        assertFalse(espressoNitroTEEVerifier.isSignerValid(randomSigner, ServiceType.BatchPoster));
    }

    /**
     * @dev Test: Service type isolation in isSignerValid
     */
    function test_IsSignerValid_ServiceIsolation() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);

        // Register for BatchPoster only
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
        address signer = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;

        // Valid for BatchPoster
        assertTrue(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.BatchPoster));

        // NOT valid for CaffNode
        assertFalse(espressoNitroTEEVerifier.isSignerValid(signer, ServiceType.CaffNode));

        vm.stopPrank();
    }
}

