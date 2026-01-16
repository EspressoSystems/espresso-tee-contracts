// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    VerificationResult
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {ServiceType} from "../types/Types.sol";

interface IEspressoNitroTEEVerifier {
    // This error is thrown when the PCR0 values don't match
    error InvalidAWSEnclaveHash();
    // This error is thrown when the ZK proof verification fails
    error VerificationFailed(VerificationResult result);
    // This error is thrown when the NitroEnclaveVerifier address is invalid
    error InvalidNitroEnclaveVerifierAddress();

    event AWSServiceEnclaveHashSet(
        bytes32 indexed enclaveHash,
        bool indexed valid,
        ServiceType indexed service
    );
    event AWSNitroServiceRegistered(
        address indexed signer,
        bytes32 indexed enclaveHash,
        ServiceType indexed service
    );
    event DeletedAWSRegisteredService(
        address indexed signer,
        ServiceType indexed service
    );
    event NitroEnclaveVerifierSet(address nitroEnclaveVerifierAddress);

    /*
     * @notice This function is for registering AWS Nitro TEE Caff Nodes and is a helper function for the EspressoTEEVerifier
     */
    function registerCaffNode(
        bytes calldata output,
        bytes calldata proofBytes
    ) external;

    /*
     * @notice This function is for registering AWS Nitro Batch Posters and is a helper function for the EspressoTEEVerifier
     */
    function registerBatchPoster(
        bytes calldata output,
        bytes calldata proofBytes
    ) external;

    /*
     * @notice This function is for checking the registration status of AWS Nitro TEE Batch Posters and is a helper function for the EspressoTEEVerifier
     */
    function registeredBatchPosters(
        address signer
    ) external view returns (bool);

    /*
     * @notice This function is for checking the registration status of AWS Nitro TEE Caff Nodes and is a helper function for the EspressoTEEVerifier
     */
    function registeredCaffNodes(address signer) external view returns (bool);

    /*
     * @notice This function is for checking the registration status of AWS Nitro TEE Batch Poster enclave hashes and is a helper function for the EspressoTEEVerifier
     */
    function registeredBatchPosterEnclaveHashes(
        bytes32 enclaveHash
    ) external view returns (bool);

    /*
     * @notice This function is for checking the registration status of AWS Nitro TEE Caff Node enclave hashes and is a helper function for the EspressoTEEVerifier
     */
    function registeredCaffNodeEnclaveHashes(
        bytes32 enclaveHash
    ) external view returns (bool);

    /*
     * @notice This function is responsible for setting valid enclave hashes for AWS Nitro TEE services
     */
    function setEnclaveHash(
        bytes32 enclaveHash,
        bool valid,
        ServiceType service
    ) external;
    /*
     * @notice This function is responsible for removing registered addresses from the list of valid Caff Nodes
     */
    function deleteRegisteredCaffNodes(address[] memory signers) external;
    /*
     * @notice This function is responsible for removing registered addresses from the list of valid Batch Posters
     */
    function deleteRegisteredBatchPosters(address[] memory signers) external;
    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     */
    function setNitroEnclaveVerifier(
        address nitroEnclaveVerifierAddress
    ) external;
}
