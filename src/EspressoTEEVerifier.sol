// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {EnclaveReport} from "@automata-network/dcap-attestation/contracts/types/V3Structs.sol";

/**
 * @title EspressoTEEVerifier
 *     @author Espresso Systems (https://espresso.systems)
 *     @notice This contract is used to resgister a signer which has been attested by the TEE
 */
contract EspressoTEEVerifier is Ownable2Step, IEspressoTEEVerifier {
    IEspressoSGXTEEVerifier public espressoSGXTEEVerifier;
    IEspressoNitroTEEVerifier public espressoNitroTEEVerifier;

    constructor(
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier,
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) Ownable() {
        espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
        _transferOwnership(msg.sender);
    }

    /**
     * @notice This function is used to verify the signature of the user data
     *     @param signature The signature of the user data
     *     @param userDataHash The hash of the user data
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

    /* @notice Register a new signer by verifying a quote from the TEE
        @param attestation The attestation from the TEE
        @param data when registering a signer, data can be passed for each TEE type
        which can be any additiona data that is required for registering a signer
        @param teeType The type of TEE
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
     * @notice This function retrieves whether a signer is registered or not
     *     @param signer The address of the signer
     *     @param teeType The type of TEE
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
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
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

    /**
     * @notice This function verifies a given certificate on chain
     * @param certificate The certificate from the attestation
     * @param parentCertHash The keccak256 hash over the parent certificate
     * @param isCA Is it a CA certificate if true, if false client certificate
     * @param teeType The type of TEE
     */
    function verifyCert(
        bytes calldata certificate,
        bytes32 parentCertHash,
        bool isCA,
        TeeType teeType
    ) external {
        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.verifyCert(certificate, parentCertHash, isCA);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice This function is a readonly function to check if a certificate is already verified on chain
     * @param certHash The certificate keccak256 hash
     * @param teeType The type of TEE
     */
    function certVerified(bytes32 certHash, TeeType teeType) external view returns (bool) {
        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.certVerified(certHash);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice Verify a quote from the TEE and attest on-chain
     *     The verification is considered successful if the function does not revert.
     *     @param rawQuote The quote from the TEE
     *     @param reportDataHash The hash of the report data
     *     @param teeType The type of TEE
     */
    function verifyAttestationQuote(
        bytes calldata rawQuote,
        bytes32 reportDataHash,
        TeeType teeType
    ) external view returns (EnclaveReport memory) {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.verify(rawQuote, reportDataHash);
        }
        revert UnsupportedTeeType();
    }

    /*
        @notice Set the EspressoSGXTEEVerifier
        @param _espressoSGXTEEVerifier The address of the EspressoSGXTEEVerifier
     */
    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier)
        public
        onlyOwner
    {
        espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
    }

    /*
        @notice Set the EspressoNitroTEEVerifier
        @param _espressoNitroTEEVerifier The address of the EspressoNitroTEEVerifier
     */
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        public
        onlyOwner
    {
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }
}
