// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEspressoTEEVerifier} from "../interface/IEspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../interface/IEspressoNitroTEEVerifier.sol";

/**
 * @title EspressoTEEVerifierMock
 * @notice Mock contract for TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 */
contract EspressoTEEVerifierMock is IEspressoTEEVerifier {
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
    function verify(bytes memory signature, bytes32 userDataHash, TeeType teeType)
        external
        view
        returns (bool)
    {
        address signer = ECDSA.recover(userDataHash, signature);

        if (teeType == TeeType.SGX) {
            if (!espressoSGXTEEVerifier.registeredSigners(signer)) {
                revert InvalidSignature();
            }
            return true;
        }

        if (teeType == TeeType.NITRO) {
            if (!espressoNitroTEEVerifier.registeredSigners(signer)) {
                revert InvalidSignature();
            }
            return true;
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice Register a signer - delegates to the appropriate TEE verifier
     * @param attestation The attestation (ignored in mock verifiers)
     * @param data The signer data
     * @param teeType The type of TEE
     */
    function registerSigner(bytes calldata attestation, bytes calldata data, TeeType teeType)
        external
    {
        if (teeType == TeeType.SGX) {
            espressoSGXTEEVerifier.registerSigner(attestation, data);
            return;
        }

        if (teeType == TeeType.NITRO) {
            espressoNitroTEEVerifier.registerSigner(attestation, data);
            return;
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice Check if a signer is registered
     * @param signer The address of the signer
     * @param teeType The type of TEE
     */
    function registeredSigners(address signer, TeeType teeType) external view returns (bool) {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredSigners(signer);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredSigners(signer);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice Check if an enclave hash is registered
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType)
        external
        view
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash);
        }
        revert UnsupportedTeeType();
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
