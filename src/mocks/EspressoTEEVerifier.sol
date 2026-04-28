// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IEspressoTEEVerifier} from "../interface/IEspressoTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../interface/IEspressoNitroTEEVerifier.sol";

/**
 * @title EspressoTEEVerifierMock
 * @notice Mock contract for TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 *         Uses EIP-712 typed data signing to match the real EspressoTEEVerifier.
 */
contract EspressoTEEVerifierMock is EIP712 {
    IEspressoNitroTEEVerifier public espressoNitroTEEVerifier;

    bytes32 private constant ESPRESSO_TEE_VERIFIER_TYPE_HASH =
        keccak256("EspressoTEEVerifier(bytes32 commitment)");

    function _requireNitroTeeType(IEspressoTEEVerifier.TeeType teeType) private pure {
        if (teeType != IEspressoTEEVerifier.TeeType.NITRO) {
            revert IEspressoTEEVerifier.UnsupportedTeeType(teeType);
        }
    }

    constructor(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        EIP712("EspressoTEEVerifier", "1")
    {
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
        IEspressoTEEVerifier.TeeType teeType
    ) external view returns (bool) {
        _requireNitroTeeType(teeType);

        bytes32 structHash = keccak256(abi.encode(ESPRESSO_TEE_VERIFIER_TYPE_HASH, userDataHash));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        if (!espressoNitroTEEVerifier.isSignerValid(signer)) {
            revert IEspressoTEEVerifier.InvalidSignature();
        }

        return true;
    }

    /**
     * @notice Register a signer - delegates to the Nitro TEE verifier
     * @param attestation The attestation (ignored in mock verifiers)
     * @param data The signer data
     * @param teeType The type of TEE
     */
    function registerService(
        bytes calldata attestation,
        bytes calldata data,
        IEspressoTEEVerifier.TeeType teeType
    ) external {
        _requireNitroTeeType(teeType);

        espressoNitroTEEVerifier.registerService(attestation, data);
    }

    function isSignerValid(address signer, IEspressoTEEVerifier.TeeType teeType)
        external
        view
        returns (bool)
    {
        _requireNitroTeeType(teeType);

        return espressoNitroTEEVerifier.isSignerValid(signer);
    }

    /**
     * @notice Check if an enclave hash is registered
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, IEspressoTEEVerifier.TeeType teeType)
        external
        view
        returns (bool)
    {
        _requireNitroTeeType(teeType);

        return espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash);
    }

    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        external
    {
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }
}
