// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEspressoTEEVerifier} from "../interface/IEspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../types/Types.sol";

/**
 * @title EspressoTEEVerifierMock
 * @notice Mock contract for TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoTEEVerifierMock {
    enum TeeType {
        SGX,
        NITRO,
        TESTS
    }
    IEspressoSGXTEEVerifier public espressoSGXTEEVerifier;
    IEspressoNitroTEEVerifier public espressoNitroTEEVerifier;

    constructor(
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier,
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) {
        espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }

    /**
     * @notice Verify signature from a registered signer
     * @param signature The signature of the user data
     * @param userDataHash The hash of the user data
     * @param teeType The type of TEE
     */
    function verify(
        bytes memory signature,
        bytes32 userDataHash,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        address signer = ECDSA.recover(userDataHash, signature);

        if (teeType == TeeType.SGX || teeType == TeeType.TESTS) {
            if (!espressoSGXTEEVerifier.registeredService(signer, service)) {
                revert IEspressoTEEVerifier.InvalidSignature();
            }
            return true;
        }

        if (teeType == TeeType.NITRO) {
            if (!espressoNitroTEEVerifier.registeredService(signer, service)) {
                revert IEspressoTEEVerifier.InvalidSignature();
            }
            return true;
        }
    }

    /**
     * @notice Register a signer - delegates to the appropriate TEE verifier
     * @param attestation The attestation (ignored in mock verifiers)
     * @param data The signer data
     * @param teeType The type of TEE
     */
    function registerService(
        bytes calldata attestation,
        bytes calldata data,
        TeeType teeType,
        ServiceType service
    ) external {
        if (teeType == TeeType.SGX || teeType == TeeType.TESTS) {
            espressoSGXTEEVerifier.registerService(attestation, data, service);
            return;
        }

        if (teeType == TeeType.NITRO) {
            espressoNitroTEEVerifier.registerService(attestation, data, service);
            return;
        }
    }

    /**
     * @notice Check if a signer is registered
     * @param signer The address of the signer
     * @param teeType The type of TEE
     */
    function registeredService(
        address signer,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        if (teeType == TeeType.SGX || teeType == TeeType.TESTS) {
            return espressoSGXTEEVerifier.registeredService(signer, service);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredService(signer, service);
        }
    }

    /**
     * @notice Check if an enclave hash is registered
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     */
    function registeredEnclaveHashes(
        bytes32 enclaveHash,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        if (teeType == TeeType.SGX || teeType == TeeType.TESTS) {
            return espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }
    }

    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier) external {
        espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
    }

    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external
    {
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }
}
