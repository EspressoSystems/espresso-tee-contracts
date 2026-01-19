// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {ServiceType, Unimplemented, UnsupportedServiceType} from "./types/Types.sol";

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

    // Checks if the service type is supported
    modifier onlySupportedServiceType(ServiceType service) {
        if (uint8(service) > uint8(ServiceType.CaffNode)) {
            revert UnsupportedServiceType();
        }
        _;
    }

    modifier onlySupportedTEE(TeeType teeType) {
        if (uint8(teeType) > uint8(TeeType.NITRO)) {
            revert UnsupportedServiceType();
        }
        _;
    }

    /**
     * @notice This function is used to verify the signature of the user data
     * @param signature The signature of the user data
     * @param userDataHash The hash of the user data
     * @param teeType The type of TEE
     * @param service The type of service
     */
    function verify(
        bytes memory signature,
        bytes32 userDataHash,
        TeeType teeType,
        ServiceType service
    ) external view onlySupportedTEE(teeType) onlySupportedServiceType(service) returns (bool) {
        address signer = ECDSA.recover(userDataHash, signature);
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredSigner(signer, service);
        } else {
            return espressoNitroTEEVerifier.registeredSigner(signer, service);
        }
    }

    /**
     *     @notice Register a new signer by verifying a quote from the TEE
     *     @param verificationData The data produced by the TEE for verifying it's authenticity.
     *     @param data when registering a signer, data can be passed for each TEE type
     *     which can be any additiona data that is required for registering a signer with
     *     that particular tee type
     *     @param teeType The type of TEE
     *     @param service The type of service being registered potentially affects the behavior of registration.
     */
    function registerService(
        bytes calldata verificationData,
        bytes calldata data,
        TeeType teeType,
        ServiceType service
    ) external onlySupportedTEE(teeType) onlySupportedServiceType(service) {
        if (teeType == TeeType.SGX) {
            espressoSGXTEEVerifier.registerService(verificationData, data, service);
            return;
        } else {
            espressoNitroTEEVerifier.registerService(verificationData, data, service);
            return;
        }
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     *     @param signer The address of the signer
     *     @param teeType The type of TEE
     */
    function registeredSigners(address signer, TeeType teeType, ServiceType service)
        external
        view
        onlySupportedTEE(teeType)
        onlySupportedServiceType(service)
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredSigner(signer, service);
        } else {
            return espressoNitroTEEVerifier.registeredSigner(signer, service);
        }
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
     */
    function registeredEnclaveHashes(bytes32 enclaveHash, TeeType teeType, ServiceType service)
        external
        view
        onlySupportedTEE(teeType)
        onlySupportedServiceType(service)
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        } else {
            return espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }
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

    /**
     *     @notice Set the EspressoNitroTEEVerifier
     *     @param _espressoNitroTEEVerifier The address of the EspressoNitroTEEVerifier
     */
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        public
        onlyOwner
    {
        espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }
}
