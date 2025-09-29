// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IEspressoSGXTEEVerifier} from "./IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../types/Types.sol";

interface IEspressoTEEVerifier {
    /**
     * @notice This enum is used to specify the type of TEE
     */
    enum TeeType {
        SGX,
        NITRO
    }
    // This error is thrown when the signature is invalid

    error InvalidSignature();
    // This error is thrown when the TEE type is not supported
    error UnsupportedTeeType();
    // This error is thrown when the ServiceType enum provided to a method is unsupported for that method.
    error UnsupportedServiceType();

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
    // This function can has succeeded if it does not revert.
    function registerService(
        bytes calldata verificationData,
        bytes calldata data,
        TeeType teeType,
        ServiceType serviceType
    ) external;

    // Function to retrieve whether a service is registered or not
    function registeredServices(address signer, TeeType teeType, ServiceType serviceType)
        external
        view
        returns (bool);

    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType, ServiceType serviceType)
        external
        view
        returns (bool);

    // Function to set the EspressoSGXTEEVerifier
    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier) external;

    // Function to set the EspressoNitroTEEVerifier
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external;
}
