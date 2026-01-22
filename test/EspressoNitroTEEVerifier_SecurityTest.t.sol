// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";
import {
    INitroEnclaveVerifier,
    ZkCoProcessorType,
    ZkCoProcessorConfig
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

/**
 * @title Security test to demonstrate protection against verifier key tampering
 * @dev This test shows how the validation checks protect against external configuration changes
 */
contract EspressoNitroTEEVerifierSecurityTest is Test {
    address adminTEE = address(141);
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        vm.startPrank(adminTEE);
        
        // Deploy with the real Sepolia Nitro Enclave Verifier
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * @dev Test that the contract stores the expected verifier configuration at deployment
     */
    function testExpectedConfigurationStoredAtDeployment() public view {
        // The contract should have cached the verifier ID and ZK verifier address
        bytes32 expectedVerifierId = espressoNitroTEEVerifier.expectedVerifierId();
        address expectedZkVerifier = espressoNitroTEEVerifier.expectedZkVerifier();
        
        console.log("Expected Verifier ID:");
        console.logBytes32(expectedVerifierId);
        console.log("Expected ZK Verifier:");
        console.log(expectedZkVerifier);
        
        // These should not be zero
        assertNotEq(expectedVerifierId, bytes32(0), "Verifier ID should be set");
        assertNotEq(expectedZkVerifier, address(0), "ZK Verifier should be set");
    }

    /**
     * @dev Test that registration works normally when configuration is unchanged
     */
    function testRegisterServiceWorksWithUnchangedConfiguration() public {
        vm.startPrank(adminTEE);
        vm.warp(1_764_889_188);
        
        string memory proofPath = "/test/configs/proof.json";
        string memory inputFile = string.concat(vm.projectRoot(), proofPath);
        string memory json = vm.readFile(inputFile);
        bytes memory output = vm.parseJsonBytes(json, ".raw_proof.journal");
        bytes memory proofBytes = vm.parseJsonBytes(json, ".onchain_proof");

        // This should work fine - configuration hasn't changed
        espressoNitroTEEVerifier.registerService(output, proofBytes, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * @dev Demonstrate what would happen if Automata's owner changed the configuration
     * Note: We can't actually change the external contract in the test, but we can simulate
     * the detection by deploying a mock verifier with different config
     */
    function testDetectsConfigurationChangeWhenSwitchingVerifier() public {
        vm.startPrank(adminTEE);
        
        // Deploy a mock verifier with different configuration
        MockNitroVerifierWithDifferentConfig mockVerifier = new MockNitroVerifierWithDifferentConfig();
        
        // Try to switch to the mock verifier - this should FAIL because config is different
        vm.expectRevert(
            abi.encodeWithSelector(
                IEspressoNitroTEEVerifier.VerifierConfigurationChanged.selector,
                "New verifier has different verifier ID"
            )
        );
        espressoNitroTEEVerifier.setNitroEnclaveVerifier(address(mockVerifier));
        
        vm.stopPrank();
    }

    /**
     * @dev Show that only a verifier with matching configuration can be set
     */
    function testAllowsVerifierChangeOnlyWithMatchingConfiguration() public {
        vm.startPrank(adminTEE);
        
        // Get the current expected configuration
        bytes32 currentVerifierId = espressoNitroTEEVerifier.expectedVerifierId();
        address currentZkVerifier = espressoNitroTEEVerifier.expectedZkVerifier();
        
        // Deploy a mock verifier with SAME configuration
        MockNitroVerifierWithSameConfig mockVerifier = new MockNitroVerifierWithSameConfig(
            currentVerifierId,
            currentZkVerifier
        );
        
        // This should succeed - configuration matches
        espressoNitroTEEVerifier.setNitroEnclaveVerifier(address(mockVerifier));
        
        // Verify the verifier was changed
        assertEq(
            address(espressoNitroTEEVerifier._nitroEnclaveVerifier()),
            address(mockVerifier),
            "Verifier should be updated"
        );
        
        vm.stopPrank();
    }
}

/**
 * @dev Mock verifier with different configuration to simulate attack scenario
 */
contract MockNitroVerifierWithDifferentConfig {
    function getZkConfig(ZkCoProcessorType) external pure returns (ZkCoProcessorConfig memory) {
        return ZkCoProcessorConfig({
            verifierId: bytes32(uint256(0x666)), // Malicious/different verifier ID
            verifierProofId: bytes32(0),
            aggregatorId: bytes32(0),
            zkVerifier: address(0x666) // Malicious/different ZK verifier
        });
    }
}

/**
 * @dev Mock verifier with same configuration to demonstrate allowed updates
 */
contract MockNitroVerifierWithSameConfig {
    bytes32 private _verifierId;
    address private _zkVerifier;

    constructor(bytes32 verifierId, address zkVerifier) {
        _verifierId = verifierId;
        _zkVerifier = zkVerifier;
    }

    function getZkConfig(ZkCoProcessorType) external view returns (ZkCoProcessorConfig memory) {
        return ZkCoProcessorConfig({
            verifierId: _verifierId,
            verifierProofId: bytes32(0),
            aggregatorId: bytes32(0),
            zkVerifier: _zkVerifier
        });
    }
}

