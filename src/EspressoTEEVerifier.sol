// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {ServiceType} from "./types/Types.sol";

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
    ) external view returns (bool) {
        address signer = ECDSA.recover(userDataHash, signature);
        if (teeType == TeeType.SGX) {
            if (!espressoSGXTEEVerifier.registeredService(signer, service)) {
                revert InvalidSignature();
            }
        } else {
            if (!espressoNitroTEEVerifier.registeredService(signer, service)) {
                revert InvalidSignature();
            }
        }
        return true;
    }

    /**
     *     @notice Register a new signer by verifying a quote from the TEE
     *     @param verificationData The data produced by the TEE for verifying it's authenticity.
     *     @param data when registering a signer, data can be passed for each TEE type
     *     which can be any additional data that is required for registering a signer with
     *     that particular tee type
     *     @param teeType The type of TEE
     *     @param service The type of service being registered potentially affects the behavior of registration.
     */
    function registerService(
        bytes calldata verificationData,
        bytes calldata data,
        TeeType teeType,
        ServiceType service
    ) external {
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
    function registeredService(address signer, TeeType teeType, ServiceType service)
        external
        view
        returns (bool)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredService(signer, service);
        } else {
            return espressoNitroTEEVerifier.registeredService(signer, service);
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
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        } else {
            return espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }
    }

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(bytes32 enclaveHash, TeeType teeType, ServiceType service)
        external
        view
        returns (address[] memory)
    {
        if (teeType == TeeType.SGX) {
            return espressoSGXTEEVerifier.enclaveHashSigners(enclaveHash, service);
        } else {
            return espressoNitroTEEVerifier.enclaveHashSigners(enclaveHash, service);
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
