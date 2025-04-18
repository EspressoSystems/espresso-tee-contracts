// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Header} from "@automata-network/dcap-attestation/contracts/types/CommonStruct.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";

interface IEspressoSGXTEEVerifier {
    // We only support version 3 for now
    error InvalidHeaderVersion();
    // This error is thrown when the automata verification fails
    error InvalidQuote();
    // This error is thrown when the enclave report fails to parse
    error FailedToParseEnclaveReport();
    // This error is thrown when the mrEnclave don't match
    error InvalidEnclaveHash();
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

    event EnclaveHashSet(bytes32 enclaveHash, bool valid);
    event SignerRegistered(address signer, bytes32 enclaveHash);
    event DeletedRegisteredSigner(address signer);

    function registeredSigners(address signer) external view returns (bool);
    function registeredEnclaveHash(bytes32 enclaveHash) external view returns (bool);

    function registerSigner(bytes calldata attestation, bytes calldata data) external;

    function verify(bytes calldata rawQuote, bytes32 reportDataHash)
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

    function setEnclaveHash(bytes32 enclaveHash, bool valid) external;
    function deleteRegisteredSigners(address[] memory signers) external;
}
