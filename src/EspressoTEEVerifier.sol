// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {Unimplemented, ServiceType} from "./types/Types.sol";

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
            if (!espressoSGXTEEVerifier.registeredBatchPosters(signer)) {
                revert InvalidSignature();
            }
            return true;
        }

        if (teeType == TeeType.NITRO) {
            if (!espressoNitroTEEVerifier.registeredBatchPosters(signer)) {
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
    function registerService(
        bytes calldata attestation,
        bytes calldata data,
        TeeType teeType,
        ServiceType service
    ) external {
        if (service == ServiceType.CaffNode) {
            revert Unimplemented();
        }

        if (teeType == TeeType.SGX) {
            espressoSGXTEEVerifier.registerBatchPoster(attestation, data);
            return;
        }

        if (teeType == TeeType.NITRO) {
            espressoNitroTEEVerifier.registerBatchPoster(attestation, data);
            return;
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     *     @param signer The address of the signer
     *     @param teeType The type of TEE
     */
    function registeredServices(address signer, TeeType teeType, ServiceType service)
        external
        view
        returns (bool)
    {
        if (service == ServiceType.CaffNode) {
            revert Unimplemented();
        }

        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredBatchPosters(signer);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredBatchPosters(signer);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType, ServiceType service)
        external
        view
        returns (bool)
    {
        if (service == ServiceType.CaffNode) {
            revert Unimplemented();
        }

        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredBatchPosterEnclaveHashes(enclaveHash);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(enclaveHash);
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
