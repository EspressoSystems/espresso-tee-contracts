// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Test comprehensive journal validation
 */
contract JournalValidationTest is Test {
    address adminTEE = address(141);
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * @dev Test that valid attestation passes all validations
     */
    function testValidAttestationPassesValidation() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188); // Set timestamp to match proof

        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // Should succeed with all validations
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        // Verify signer was registered
        address expectedSigner = 0xF8463E0aF00C1910402D2A51B3a8CecD0dC1c3fE;
        assertTrue(
            espressoNitroTEEVerifier.registeredService(expectedSigner, ServiceType.BatchPoster),
            "Signer should be registered"
        );

        vm.stopPrank();
    }

    /**
     * @dev Test that old attestation is rejected
     */
    function testOldAttestationRejected() public {
        vm.startPrank(adminTEE);

        // Warp to 8 days in the future (max age is 7 days)
        vm.warp(1_764_889_188 + 8 days);

        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // Should revert due to old timestamp (validated by NitroEnclaveVerifier)
        // VerificationResult.InvalidTimestamp = 3
        vm.expectRevert(
            abi.encodeWithSelector(bytes4(keccak256("VerificationFailed(uint8)")), uint8(3))
        );
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        vm.stopPrank();
    }

    /**
     * @dev Test that attestation from future is rejected
     */
    function testFutureAttestationRejected() public {
        vm.startPrank(adminTEE);

        // Warp to before the attestation timestamp
        vm.warp(1_764_889_188 - 1 days);

        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // Should revert due to future timestamp (validated by NitroEnclaveVerifier)
        // VerificationResult.InvalidTimestamp = 3
        vm.expectRevert(
            abi.encodeWithSelector(bytes4(keccak256("VerificationFailed(uint8)")), uint8(3))
        );
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);

        vm.stopPrank();
    }
}

