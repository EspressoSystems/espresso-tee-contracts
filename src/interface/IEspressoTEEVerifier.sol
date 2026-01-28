// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoSGXTEEVerifier} from "./IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../types/Types.sol";

interface IEspressoTEEVerifier {
    error InvalidVerifierAddress();

    /**
     * @notice This enum is used to specify the type of TEE
     */
    enum TeeType {
        SGX,
        NITRO
    }
    // This error is thrown when the signature is invalid

    error InvalidSignature();

    // Get address of Nitro TEE Verifier
    function espressoNitroTEEVerifier() external view returns (IEspressoNitroTEEVerifier);

    // Get addressof SGX TEE Verifier
    function espressoSGXTEEVerifier() external view returns (IEspressoSGXTEEVerifier);

    // Function to verify the signature of the user data is from a registered signer
    function verify(
        bytes memory signature,
        bytes32 userDataHash,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool);

    // Function to register a service which has been attested by a TEE or Attestation Verifier
    // This function has succeeded if it does not revert.
    function registerService(
        bytes calldata verificationData,
        bytes calldata data,
        TeeType teeType,
        ServiceType serviceType
    ) external;

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     * @param serviceType The service type (BatchPoster or CaffNode)
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType, ServiceType serviceType)
        external
        view
        returns (bool);

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     * @param serviceType The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     *
     */
    function enclaveHashSigners(bytes32 enclaveHash, TeeType teeType, ServiceType serviceType)
        external
        view
        returns (address[] memory);

    // Function to set the EspressoSGXTEEVerifier
    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier) external;

    // Function to set the EspressoNitroTEEVerifier
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external;

    // Admin functions routed through the tee verifier
    function setEnclaveHash(bytes32 enclaveHash, bool valid, TeeType teeType, ServiceType service)
        external;

    function deleteEnclaveHashes(
        bytes32[] memory enclaveHashes,
        TeeType teeType,
        ServiceType service
    ) external;

    function setQuoteVerifier(address quoteVerifier) external;

    function setNitroEnclaveVerifier(address nitroVerifier) external;
}
