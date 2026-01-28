// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableWithGuardiansUpgradeable} from "./OwnableWithGuardiansUpgradeable.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {ServiceType} from "./types/Types.sol";

/**
 * @title EspressoTEEVerifier
 *     @author Espresso Systems (https://espresso.systems)
 *     @notice This contract is used to resgister a signer which has been attested by the TEE
 */
contract EspressoTEEVerifier is
    OwnableWithGuardiansUpgradeable,
    IEspressoTEEVerifier
{
    /// @custom:storage-location erc7201:espresso.storage.EspressoTEEVerifier
    struct EspressoTEEVerifierStorage {
        IEspressoSGXTEEVerifier espressoSGXTEEVerifier;
        IEspressoNitroTEEVerifier espressoNitroTEEVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.EspressoTEEVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ESPRESSO_TEE_VERIFIER_STORAGE_SLOT =
        0x89639f446056f5d7661bbd94e8ab0617a80058ed7b072845818d4b93332e4800;

    function _layout()
        private
        pure
        returns (EspressoTEEVerifierStorage storage $)
    {
        assembly {
            $.slot := ESPRESSO_TEE_VERIFIER_STORAGE_SLOT
        }
    }

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier,
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) public initializer {
        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
        $.espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
        __OwnableWithGuardians_init(_owner);
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
        EspressoTEEVerifierStorage storage $ = _layout();
        address signer = ECDSA.recover(userDataHash, signature);
        if (teeType == TeeType.SGX) {
            if (!$.espressoSGXTEEVerifier.registeredService(signer, service)) {
                revert InvalidSignature();
            }
        } else {
            if (
                !$.espressoNitroTEEVerifier.registeredService(signer, service)
            ) {
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
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            $.espressoSGXTEEVerifier.registerService(
                verificationData,
                data,
                service
            );
            return;
        } else {
            $.espressoNitroTEEVerifier.registerService(
                verificationData,
                data,
                service
            );
            return;
        }
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     *     @param signer The address of the signer
     *     @param teeType The type of TEE
     */
    function registeredService(
        address signer,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            return $.espressoSGXTEEVerifier.registeredService(signer, service);
        } else {
            return
                $.espressoNitroTEEVerifier.registeredService(signer, service);
        }
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     *     @param enclaveHash The hash of the enclave
     *     @param teeType The type of TEE
     */
    function registeredEnclaveHashes(
        bytes32 enclaveHash,
        TeeType teeType,
        ServiceType service
    ) external view returns (bool) {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            return
                $.espressoSGXTEEVerifier.registeredEnclaveHash(
                    enclaveHash,
                    service
                );
        } else {
            return
                $.espressoNitroTEEVerifier.registeredEnclaveHash(
                    enclaveHash,
                    service
                );
        }
    }

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(
        bytes32 enclaveHash,
        TeeType teeType,
        ServiceType service
    ) external view returns (address[] memory) {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            return
                $.espressoSGXTEEVerifier.enclaveHashSigners(
                    enclaveHash,
                    service
                );
        } else {
            return
                $.espressoNitroTEEVerifier.enclaveHashSigners(
                    enclaveHash,
                    service
                );
        }
    }

    /**
     *     @notice Set the EspressoSGXTEEVerifier
     *     @param _espressoSGXTEEVerifier The address of the EspressoSGXTEEVerifier
     */
    function setEspressoSGXTEEVerifier(
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier
    ) public onlyOwner {
        if (address(_espressoSGXTEEVerifier) == address(0)) {
            revert InvalidVerifierAddress();
        }

        _layout().espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
    }

    /**
     * @notice Set the EspressoNitroTEEVerifier
     * @param _espressoNitroTEEVerifier The address of the EspressoNitroTEEVerifier
     */
    function setEspressoNitroTEEVerifier(
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) public onlyOwner {
        if (address(_espressoNitroTEEVerifier) == address(0)) {
            revert InvalidVerifierAddress();
        }

        _layout().espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
    }

    /**
     * @notice Allows the owner or guardian to set enclave hashes
     * @param enclaveHash The enclave hash to set
     * @param valid Whether the enclave hash is valid or not
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(
        bytes32 enclaveHash,
        bool valid,
        TeeType teeType,
        ServiceType service
    ) external onlyGuardianOrOwner {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            $.espressoSGXTEEVerifier.setEnclaveHash(
                enclaveHash,
                valid,
                service
            );
        } else {
            $.espressoNitroTEEVerifier.setEnclaveHash(
                enclaveHash,
                valid,
                service
            );
        }
    }

    /**
     * @notice Allows the owner or guardian to delete enclave hashes
     * @param enclaveHashes The list of enclave hashes to delete
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(
        bytes32[] memory enclaveHashes,
        TeeType teeType,
        ServiceType service
    ) external onlyGuardianOrOwner {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            $.espressoSGXTEEVerifier.deleteEnclaveHashes(
                enclaveHashes,
                service
            );
        } else {
            $.espressoNitroTEEVerifier.deleteEnclaveHashes(
                enclaveHashes,
                service
            );
        }
    }

    /**
     * @notice Set the quote verifier for SGX TEEs
     * @param quoteVerifier The address of the quote verifier
     */
    function setQuoteVerifier(address quoteVerifier) external onlyOwner {
        _layout().espressoSGXTEEVerifier.setQuoteVerifier(quoteVerifier);
    }

    /**
     * @notice Set the nitro enclave verifier for Nitro TEEs
     * @param nitroVerifier The address of the nitro enclave verifier
     */
    function setNitroEnclaveVerifier(address nitroVerifier) external onlyOwner {
        _layout().espressoNitroTEEVerifier.setNitroEnclaveVerifier(
            nitroVerifier
        );
    }

    /**
     * @notice Get the EspressoSGXTEEVerifier address
     * @return The EspressoSGXTEEVerifier interface
     */
    function espressoSGXTEEVerifier()
        external
        view
        returns (IEspressoSGXTEEVerifier)
    {
        return _layout().espressoSGXTEEVerifier;
    }

    /**
     * @notice Get the EspressoNitroTEEVerifier address
     * @return The EspressoNitroTEEVerifier interface
     */
    function espressoNitroTEEVerifier()
        external
        view
        returns (IEspressoNitroTEEVerifier)
    {
        return _layout().espressoNitroTEEVerifier;
    }
}
