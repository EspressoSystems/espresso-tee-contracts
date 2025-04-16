// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Header} from "@automata-network/dcap-attestation/contracts/types/CommonStruct.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";
import {IEspressoSGXTEEVerifier} from "./IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./IEspressoNitroTEEVerifier.sol";

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

    // Function to verify the signature of the user data is from a registered signer
    function verify(bytes memory signature, bytes32 userDataHash, TeeType teeType)
        external
        view
        returns (bool);

    // Function to register a signer which has been attested by the TEE
    function registerSigner(bytes calldata attestation, bytes calldata data, TeeType teeType)
        external;

    // Function to retrieve whether a signer is registered or not
    function registeredSigners(address signer, TeeType teeType) external view returns (bool);

    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType)
        external
        view
        returns (bool);

    function verifyCert(bytes calldata certificate, bytes32 parentCertHash, bool isCA) external;
    function certVerified(bytes32 parentCertHash) external view returns (bytes memory);

    // Function to set the EspressoSGXTEEVerifier
    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier) external;

    // Function to set the EspressoNitroTEEVerifier
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external;
}
