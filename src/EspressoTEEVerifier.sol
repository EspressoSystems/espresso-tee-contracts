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

    /**
     * @notice This function is used to verify the signature of the user data
     *     @param signature The signature of the user data
     *     @param userDataHash The hash of the user data
     */
    function verify(bytes memory signature, bytes32 userDataHash, TeeType teeType, ServiceType service)
        external
        view
        returns (bool)
    {
        address signer = ECDSA.recover(userDataHash, signature);

        if (service == ServiceType.BatchPoster){
            checkRegisteredBatchPosters(signer, teeType);
        } else if (service == ServiceType.CaffNode){
            checkRegisteredCaffNodes(signer, teeType);
        } else {
            revert UnsupportedServiceType();
        }
        
    }

    /* @notice Register a new signer by verifying a quote from the TEE
        @param verificationData The data produced by the TEE for verifying it's authenticity.
        @param data when registering a signer, data can be passed for each TEE type
        which can be any additiona data that is required for registering a signer with
        that particular tee type
        @param teeType The type of TEE
        @param service The type of service being registered potentially affects the behavior of registration.
     */
    function registerService(
        bytes calldata verificationData,
        bytes calldata data,
        TeeType teeType,
        ServiceType service
    ) external {
        if (service == ServiceType.BatchPoster) {
            registerBatchPosterHelper(verificationData, data, teeType);
            return;
        } else if (service == ServiceType.CaffNode) {
            registerCaffNodeHelper(verificationData, data, teeType);
            return;
        } else{
            revert UnsupportedServiceType();
        }
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
        if (service == ServiceType.BatchPoster){
            checkRegisteredBatchPosters(signer, teeType);
        } else if (service == ServiceType.CaffNode){
            checkRegisteredCaffNodes(signer, teeType);
        } else {
            revert UnsupportedServiceType();
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
        returns (bool)
    {
        if (service == ServiceType.BatchPoster){
            registeredBatchPosterEnclaveHashes(enclaveHash, teeType);
        } else if (service == ServiceType.CaffNode){
            registeredCaffNodeEnclaveHashes(enclaveHash, teeType);
        } else {
            revert UnsupportedServiceType();
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

    /*
    * @notice: This is a helper function for reducing code duplication when checking for
    *          registered services; Namely, this handles the batch posters.
    *
    */
    function checkRegisteredBatchPosters(address signer, TeeType teeType) public view returns(bool){

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

    }

    /*
    * @notice: This is a helper function for reducing code duplication when checking for
    *          registered services; Namely, this handles the caff nodes.
    *
    */
    function checkRegisteredCaffNodes(address signer, TeeType teeType) public view returns(bool){

        if (teeType == TeeType.SGX) {
            if (!espressoSGXTEEVerifier.registeredCaffNodes(signer)) {
                revert InvalidSignature();
            }
            return true;
        }

        if (teeType == TeeType.NITRO) {
            if (!espressoNitroTEEVerifier.registeredCaffNodes(signer)) {
                revert InvalidSignature();
            }
            return true;
        }

    }

    function registerBatchPosterHelper(bytes calldata verificationData, bytes calldata data, TeeType teeType)
        private
        {
        if (teeType == TeeType.SGX) {
            espressoSGXTEEVerifier.registerBatchPoster(verificationData, data);
            return;
        }

        if (teeType == TeeType.NITRO) {
            espressoNitroTEEVerifier.registerBatchPoster(verificationData, data);
            return;
        }
        revert UnsupportedTeeType();
    }

    function registerCaffNodeHelper(bytes calldata verificationData, bytes calldata data, TeeType teeType)
        private
    {
        if (teeType == TeeType.SGX) {
            espressoSGXTEEVerifier.registerCaffNode(verificationData, data);
            return;
        }

        if (teeType == TeeType.NITRO) {
            espressoNitroTEEVerifier.registerCaffNode(verificationData, data);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
     */
    function registeredBatchPosterEnclaveHashes(bytes32 enclaveHash, TeeType teeType)
        private
        view
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredBatchPosterEnclaveHashes(enclaveHash);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(enclaveHash);
        }
        revert UnsupportedTeeType();
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
     */
    function registeredCaffNodeEnclaveHashes(bytes32 enclaveHash, TeeType teeType)
        private
        view
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredCaffNodeEnclaveHashes(enclaveHash);
        }

        if (teeType == TeeType.NITRO) {
            return espressoNitroTEEVerifier.registeredCaffNodeEnclaveHashes(enclaveHash);
        }
        revert UnsupportedTeeType();
    }
}
