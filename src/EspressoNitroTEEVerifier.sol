// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "./types/Types.sol";
import {
    INitroEnclaveVerifier,
    VerifierJournal,
    ZkCoProcessorType,
    VerificationResult,
    ZkCoProcessorConfig
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TEEHelper} from "./TEEHelper.sol";

/**
 * @title  Verifies quotes from the AWS Nitro Enclave (TEE) and attests on-chain
 * @notice Contains the logic to verify zk proof of the attestation on-chain. It uses the EspressoNitroTEEVerifier contract
 *         from `automata` to verify the proof.
 */
contract EspressoNitroTEEVerifier is IEspressoNitroTEEVerifier, TEEHelper {
    using EnumerableSet for EnumerableSet.AddressSet;
    INitroEnclaveVerifier public _nitroEnclaveVerifier;
    
    // Expected ZK verifier configuration - immutable to prevent tampering
    bytes32 public immutable expectedVerifierId;
    address public immutable expectedZkVerifier;

    constructor(INitroEnclaveVerifier nitroEnclaveVerifier) TEEHelper() {
        require(address(nitroEnclaveVerifier) != address(0), "NitroEnclaveVerifier cannot be zero");
        _nitroEnclaveVerifier = nitroEnclaveVerifier;
        
        // Cache the expected ZK configuration at deployment to detect tampering
        ZkCoProcessorConfig memory config = nitroEnclaveVerifier.getZkConfig(ZkCoProcessorType.Succinct);
        require(config.verifierId != bytes32(0), "Verifier ID not configured");
        require(config.zkVerifier != address(0), "ZK Verifier not configured");
        
        expectedVerifierId = config.verifierId;
        expectedZkVerifier = config.zkVerifier;
    }

    /**
     * @notice This function registers a new Service by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     * @param service The service type (BatchPoster or CaffNode)
     */
    function registerService(bytes calldata output, bytes calldata proofBytes, ServiceType service)
        external
    {
        // SECURITY: Verify that the external contract hasn't changed its ZK configuration
        _validateZkConfiguration();
        
        VerifierJournal memory journal = _nitroEnclaveVerifier.verify(
            output,
            // Currently only Succinct ZK coprocessor is supported
            ZkCoProcessorType.Succinct,
            proofBytes
        );

        if (journal.result != VerificationResult.Success) {
            revert VerificationFailed(journal.result);
        }

        // we hash the pcr0 value to get the the pcr0Hash and then
        // check if the given hash has been registered in the contract by the owner
        // this allows us to verify that the registerSigner request is coming from a TEE
        // which is trusted
        bytes32 pcr0Hash =
            keccak256(abi.encodePacked(journal.pcrs[0].value.first, journal.pcrs[0].value.second));

        if (!registeredEnclaveHashes[service][pcr0Hash]) {
            revert InvalidEnclaveHash(pcr0Hash, service);
        }

        // The publicKey's first byte 0x04 byte followed which only determine if the public key is compressed or not.
        // so we ignore the first byte.
        bytes memory publicKeyWithoutPrefix = new bytes(journal.publicKey.length - 1);
        for (uint256 i = 1; i < journal.publicKey.length; i++) {
            publicKeyWithoutPrefix[i - 1] = journal.publicKey[i];
        }

        bytes32 publicKeyHash = keccak256(publicKeyWithoutPrefix);
        // Note: We take the keccak hash first to derive the address.
        // This is the same which the go ethereum crypto library is doing for PubkeyToAddress()
        address enclaveAddress = address(uint160(uint256(publicKeyHash)));

        // Mark the signer as registered
        if (!registeredServices[service][enclaveAddress]) {
            registeredServices[service][enclaveAddress] = true;
            // slither-disable-next-line unused-return
            enclaveHashToSigner[service][pcr0Hash].add(enclaveAddress);
            emit ServiceRegistered(enclaveAddress, pcr0Hash, service);
        }
    }

    /**
     * @notice Internal function to validate that the external verifier configuration hasn't been tampered with
     * @dev Reverts if the verifier ID or ZK verifier address has changed from the expected values
     */
    function _validateZkConfiguration() internal view {
        ZkCoProcessorConfig memory currentConfig = _nitroEnclaveVerifier.getZkConfig(ZkCoProcessorType.Succinct);
        
        if (currentConfig.verifierId != expectedVerifierId) {
            revert VerifierConfigurationChanged("Verifier ID changed");
        }
        
        if (currentConfig.zkVerifier != expectedZkVerifier) {
            revert VerifierConfigurationChanged("ZK Verifier address changed");
        }
    }

    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     * @param nitroEnclaveVerifier The address of the NitroEnclaveVerifier contract
     * @dev The new verifier MUST have the same ZK configuration as the original to prevent security bypass
     */
    function setNitroEnclaveVerifier(address nitroEnclaveVerifier) external onlyOwner {
        if (nitroEnclaveVerifier == address(0)) {
            revert InvalidNitroEnclaveVerifierAddress();
        }
        
        // SECURITY: Verify that the new verifier has the same ZK configuration
        INitroEnclaveVerifier newVerifier = INitroEnclaveVerifier(nitroEnclaveVerifier);
        ZkCoProcessorConfig memory newConfig = newVerifier.getZkConfig(ZkCoProcessorType.Succinct);
        
        if (newConfig.verifierId != expectedVerifierId) {
            revert VerifierConfigurationChanged("New verifier has different verifier ID");
        }
        
        if (newConfig.zkVerifier != expectedZkVerifier) {
            revert VerifierConfigurationChanged("New verifier has different ZK verifier address");
        }
        
        _nitroEnclaveVerifier = newVerifier;
        emit NitroEnclaveVerifierSet(nitroEnclaveVerifier);
    }
}
