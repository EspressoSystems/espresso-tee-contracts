// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoNitroTEEVerifier} from "./IEspressoNitroTEEVerifier.sol";

interface IEspressoTEEVerifier {
    error InvalidVerifierAddress();
    error UnsupportedTeeType(TeeType teeType);
    event EspressoNitroTEEVerifierSet(address indexed oldVerifier, address indexed newVerifier);

    /**
     * @notice This enum is used to specify the type of TEE
     */
    enum TeeType {
        NITRO
    }
    // This error is thrown when the signature is invalid

    error InvalidSignature();

    // Get address of Nitro TEE Verifier
    function espressoNitroTEEVerifier() external view returns (IEspressoNitroTEEVerifier);

    // Function to verify the signature of the user data is from a registered signer
    function verify(bytes memory signature, bytes32 userDataHash, TeeType teeType)
        external
        view
        returns (bool);

    // Function to register a service which has been attested by a TEE or Attestation Verifier
    // This function has succeeded if it does not revert.
    function registerService(bytes calldata verificationData, bytes calldata data, TeeType teeType)
        external;

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType)
        external
        view
        returns (bool);

    /**
     * @notice This function checks if a signer is valid for a given TEE type
     * @param signer The address of the signer
     * @param teeType The type of TEE
     * @return bool True if the signer is valid, false otherwise
     */
    function isSignerValid(address signer, TeeType teeType) external view returns (bool);

    // Function to set the EspressoNitroTEEVerifier
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external;

    // Admin functions routed through the tee verifier
    function setEnclaveHash(bytes32 enclaveHash, bool valid, TeeType teeType) external;

    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, TeeType teeType) external;

    function setNitroEnclaveVerifier(address nitroVerifier) external;
}
