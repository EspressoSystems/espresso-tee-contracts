// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";

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
        // Adjusting ECDSA signature 'v' value for Ethereum compatibility
        // Get `v` from the signature and verify the byte is in expected format for openzeppelin `ECDSA.recover`
        // https://github.com/ethereum/go-ethereum/issues/19751#issuecomment-504900739
        uint8 v = uint8(signature[64]);
        if (v == 0 || v == 1) {
            signature[64] = bytes1(v + 27);
        }
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
