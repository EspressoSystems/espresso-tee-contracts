// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {IEspressoTEEVerifier} from "../interface/IEspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../interface/IEspressoNitroTEEVerifier.sol";
import {ServiceType} from "../types/Types.sol";

/**
 * @title EspressoTEEVerifierMock
 * @notice Mock contract for TEE verification. Skips all attestation verification
 *         but still requires signers to be registered before they can be used.
 *         Uses EIP-712 typed data signing to match the real EspressoTEEVerifier.
 */
contract EspressoTEEVerifierMock is EIP712 {
    IEspressoSGXTEEVerifier public espressoSGXTEEVerifier;
    IEspressoNitroTEEVerifier public espressoNitroTEEVerifier;
    mapping(address => uint256) public signerNonces;

    bytes32 private constant ESPRESSO_TEE_VERIFIER_TYPE_HASH =
        keccak256("EspressoTEEVerifier(bytes32 commitment,uint256 nonce)");

    constructor(
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier,
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) EIP712("EspressoTEEVerifier", "1") {
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
        IEspressoTEEVerifier.TeeType teeType,
        ServiceType service
    ) external returns (bool) {
        uint256 addressNonce = signerNonces[msg.sender];
        bytes32 structHash =
            keccak256(abi.encode(ESPRESSO_TEE_VERIFIER_TYPE_HASH, userDataHash, addressNonce));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);

        if (teeType == IEspressoTEEVerifier.TeeType.SGX) {
            if (!espressoSGXTEEVerifier.isSignerValid(signer, service)) {
                revert IEspressoTEEVerifier.InvalidSignature();
            }
        } else if (teeType == IEspressoTEEVerifier.TeeType.NITRO) {
            if (!espressoNitroTEEVerifier.isSignerValid(signer, service)) {
                revert IEspressoTEEVerifier.InvalidSignature();
            }
        }

        signerNonces[msg.sender] += 1;
        return true;
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
        IEspressoTEEVerifier.TeeType teeType,
        ServiceType service
    ) external {
        if (teeType == IEspressoTEEVerifier.TeeType.SGX) {
            espressoSGXTEEVerifier.registerService(attestation, data, service);
            return;
        }

        if (teeType == IEspressoTEEVerifier.TeeType.NITRO) {
            espressoNitroTEEVerifier.registerService(attestation, data, service);
            return;
        }
    }

    function isSignerValid(
        address signer,
        IEspressoTEEVerifier.TeeType teeType,
        ServiceType serviceType
    ) external view returns (bool) {
        if (teeType == IEspressoTEEVerifier.TeeType.SGX) {
            return espressoSGXTEEVerifier.isSignerValid(signer, serviceType);
        }

        if (teeType == IEspressoTEEVerifier.TeeType.NITRO) {
            return espressoNitroTEEVerifier.isSignerValid(signer, serviceType);
        }
    }

    /**
     * @notice Check if an enclave hash is registered
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     */
    function registeredEnclaveHashes(
        bytes32 enclaveHash,
        IEspressoTEEVerifier.TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        if (teeType == IEspressoTEEVerifier.TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }

        if (teeType == IEspressoTEEVerifier.TeeType.NITRO) {
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
