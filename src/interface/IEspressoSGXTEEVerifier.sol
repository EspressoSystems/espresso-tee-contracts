// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Header} from "@automata-network/dcap-attestation/contracts/types/CommonStruct.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";
import "../types/Types.sol";
import "./ITEEVerifier.sol";

interface IEspressoSGXTEEVerifier is ITEEVerifier {
    // We only support version 3 for now
    error InvalidHeaderVersion();
    // This error is thrown when the automata verification fails
    error InvalidQuote();
    // This error is thrown when the enclave report fails to parse
    error FailedToParseEnclaveReport();
    // This error is thrown when the reportDataHash doesn't match the hash signed by the TEE
    error InvalidReportDataHash();
    // This error is thrown when the reportData is too short
    error ReportDataTooShort();
    // This error is thrown when the data length is invalid
    error InvalidDataLength();
    // This error is thrown when the quote verifier address is invalid
    error InvalidQuoteVerifierAddress();

    event QuoteVerifierSet(address quoteVerifierAddress);

    /*
     * @notice This function is for registering Intel SGX TEE Batch Posters and is a helper function for the EspressoTEEVerifier
     */
    function registerService(bytes calldata attestation, bytes calldata data, ServiceType service)
        external;

    /*
     * @notice This function sets the QuoteVerifier contract address
     */
    function setQuoteVerifier(address quoteVerifierAddress) external;
}
