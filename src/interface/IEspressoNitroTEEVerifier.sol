// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {VerificationResult} from
    "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {ServiceType} from "../types/Types.sol";
import "./ITEEHelper.sol";

interface IEspressoNitroTEEVerifier is ITEEHelper {
    // This error is thrown when the ZK proof verification fails
    error VerificationFailed(VerificationResult result);
    // This error is thrown when the NitroEnclaveVerifier address is invalid
    error InvalidNitroEnclaveVerifierAddress();
    // This error is thrown when the external verifier configuration has been changed
    error VerifierConfigurationChanged(string reason);

    event NitroEnclaveVerifierSet(address nitroEnclaveVerifierAddress);

    /*
     * @notice This function registers a new Service by verifying an attestation from the AWS Nitro Enclave (TEE)
     * The signer is not the caller of the function but the address which was generated inside the TEE.
     * @param output The public output of the ZK proof
     * @param proofBytes The cryptographic proof bytes over attestation
     * @param service The service type (BatchPoster or CaffNode)
     */
    function registerService(bytes calldata output, bytes calldata proofBytes, ServiceType service)
        external;

    /*
     * @notice This function sets the NitroEnclaveVerifier contract address
     */
    function setNitroEnclaveVerifier(address nitroEnclaveVerifierAddress) external;
}
