// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Header} from "@automata-network/dcap-attestation/contracts/types/CommonStruct.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";
import "../types/Types.sol";

interface IEspressoSGXTEEVerifier {
    // We only support version 3 for now
    error InvalidHeaderVersion();
    // This error is thrown when the automata verification fails
    error InvalidQuote();
    // This error is thrown when the enclave report fails to parse
    error FailedToParseEnclaveReport();
    // This error is thrown when the mrEnclave don't match
    error InvalidEnclaveHash(bytes32 enclaveHash, ServiceType service);
    // This error is thrown when the reportDataHash doesn't match the hash signed by the TEE
    error InvalidReportDataHash();
    // This error is thrown when the reportData is too short
    error ReportDataTooShort();
    // This error is thrown when the data length is invalid
    error InvalidDataLength();
    // This error is thrown when the signer address is invalid
    error InvalidSignerAddress();
    // This error is thrown when the quote verifier address is invalid
    error InvalidQuoteVerifierAddress();

    event EnclaveHashSet(
        bytes32 indexed enclaveHash, bool indexed valid, ServiceType indexed service
    );
    event SGXServiceRegistered(
        address indexed signer, bytes32 indexed enclaveHash, ServiceType indexed service
    );
    event DeletedRegisteredService(address indexed signer, ServiceType indexed service);

    /*
    * @notice This function is for checking the registration status of Intel SGX TEE Batch Posters and is a helper function for the EspressoTEEVerifier
    */
    function registeredBatchPosters(address signer) external view returns (bool);

    /*
    * @notice This function is for checking the registration status of Intel SGX TEE Caff Nodes and is a helper function for the EspressoTEEVerifier
    */
    function registeredCaffNodes(address signer) external view returns (bool);

    function registeredBatchPosterEnclaveHashes(bytes32 enclaveHash) external view returns (bool);

    function registeredCaffNodeEnclaveHashes(bytes32 enclaveHash) external view returns (bool);

    /*
    * @notice This function is for registering Intel SGX TEE Batch Posters and is a helper function for the EspressoTEEVerifier
    */
    function registerBatchPoster(bytes calldata attestation, bytes calldata data) external;
    /*
    * @notice This function is for registering Intel SGX TEE Batch Posters and is a helper function for the EspressoTEEVerifier
    */
    function registerCaffNode(bytes calldata attestation, bytes calldata data) external;

    function verify(bytes calldata rawQuote, bytes32 reportDataHash, ServiceType service)
        external
        view
        returns (EnclaveReport memory);

    function parseQuoteHeader(bytes calldata rawQuote)
        external
        pure
        returns (Header memory header);

    function parseEnclaveReport(bytes memory rawEnclaveReport)
        external
        pure
        returns (bool success, EnclaveReport memory enclaveReport);
    /*
    * @notice: This function is responsible for setting the validity of enclave hashes in this inner TEEVerifier contract, It will be 
    */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType serviceType) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Caff Nodes
    */
    function deleteRegisteredCaffNodes(address[] memory signers) external;
    /*
    * @notice This function is responsible for removing registered addresses from the list of valid Batch Posters
    */
    function deleteRegisteredBatchPosters(address[] memory signers) external;
}
