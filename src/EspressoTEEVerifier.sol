// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableWithGuardiansUpgradeable} from "./OwnableWithGuardiansUpgradeable.sol";
import {IEspressoSGXTEEVerifier} from "./interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
import {ServiceType} from "./types/Types.sol";
import {
    EIP712Upgradeable
} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/**
 * @title EspressoTEEVerifier
 *     @author Espresso Systems (https://espresso.systems)
 *     @notice This contract is used to register a signer which has been attested by the TEE
 */
contract EspressoTEEVerifier is
    OwnableWithGuardiansUpgradeable,
    IEspressoTEEVerifier,
    EIP712Upgradeable
{
    /// @custom:storage-location erc7201:espresso.storage.EspressoTEEVerifier
    struct EspressoTEEVerifierStorage {
        IEspressoSGXTEEVerifier espressoSGXTEEVerifier;
        IEspressoNitroTEEVerifier espressoNitroTEEVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.EspressoTEEVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ESPRESSO_TEE_VERIFIER_STORAGE_SLOT =
        0x89639f446056f5d7661bbd94e8ab0617a80058ed7b072845818d4b93332e4800;

    bytes32 private constant ESPRESSO_TEE_VERIFIER_TYPE_HASH =
        keccak256("EspressoTEEVerifier(bytes32 commitment)");

    function _layout() private pure returns (EspressoTEEVerifierStorage storage $) {
        assembly {
            $.slot := ESPRESSO_TEE_VERIFIER_STORAGE_SLOT
        }
    }

    constructor() {
        _disableInitializers();
    }

    /**
     * @notice Initializes verifier contracts and ownership for this proxy instance.
     * @param _owner The owner address that can manage verifier configuration.
     * @param _espressoSGXTEEVerifier The SGX verifier used for SGX-based attestations.
     * @param _espressoNitroTEEVerifier The Nitro verifier used for Nitro-based attestations.
     */
    function initialize(
        address _owner,
        IEspressoSGXTEEVerifier _espressoSGXTEEVerifier,
        IEspressoNitroTEEVerifier _espressoNitroTEEVerifier
    ) public initializer {
        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
        $.espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
        __OwnableWithGuardians_init(_owner);
        __EIP712_init("EspressoTEEVerifier", "1");
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
        bytes32 structHash = keccak256(abi.encode(ESPRESSO_TEE_VERIFIER_TYPE_HASH, userDataHash));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        if (teeType == TeeType.SGX) {
            // Use isSignerValid to check both registration AND hash validity
            if (!$.espressoSGXTEEVerifier.isSignerValid(signer, service)) {
                revert InvalidSignature();
            }
        } else {
            // Use isSignerValid to check both registration AND hash validity
            if (!$.espressoNitroTEEVerifier.isSignerValid(signer, service)) {
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
            $.espressoSGXTEEVerifier.registerService(verificationData, data, service);
            return;
        } else {
            $.espressoNitroTEEVerifier.registerService(verificationData, data, service);
            return;
        }
    }

    /**
     * @notice This function checks if a signer is valid for a given TEE type and service
     * @param signer The address of the signer
     * @param teeType The type of TEE
     * @param serviceType The service type (BatchPoster or CaffNode)
     */
    function isSignerValid(address signer, TeeType teeType, ServiceType serviceType)
        external
        view
        returns (bool)
    {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            return $.espressoSGXTEEVerifier.isSignerValid(signer, serviceType);
        } else {
            return $.espressoNitroTEEVerifier.isSignerValid(signer, serviceType);
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
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            return $.espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        } else {
            return $.espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash, service);
        }
    }

    /**
     *     @notice Set the EspressoSGXTEEVerifier
     *     @param _espressoSGXTEEVerifier The address of the EspressoSGXTEEVerifier
     */
    function setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier _espressoSGXTEEVerifier)
        public
        onlyOwner
    {
        if (address(_espressoSGXTEEVerifier) == address(0)) {
            revert InvalidVerifierAddress();
        }
        EspressoTEEVerifierStorage storage $ = _layout();
        address oldVerifier = address($.espressoSGXTEEVerifier);
        address newVerifier = address(_espressoSGXTEEVerifier);
        $.espressoSGXTEEVerifier = _espressoSGXTEEVerifier;
        emit EspressoSGXTEEVerifierSet(oldVerifier, newVerifier);
    }

    /**
     * @notice Set the EspressoNitroTEEVerifier
     * @param _espressoNitroTEEVerifier The address of the EspressoNitroTEEVerifier
     */
    function setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        public
        onlyOwner
    {
        if (address(_espressoNitroTEEVerifier) == address(0)) {
            revert InvalidVerifierAddress();
        }
        EspressoTEEVerifierStorage storage $ = _layout();
        address oldVerifier = address($.espressoNitroTEEVerifier);
        address newVerifier = address(_espressoNitroTEEVerifier);
        $.espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
        emit EspressoNitroTEEVerifierSet(oldVerifier, newVerifier);
    }

    /**
     * @notice Allows the owner or guardian to set enclave hashes
     * @param enclaveHash The enclave hash to set
     * @param valid Whether the enclave hash is valid or not
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, TeeType teeType, ServiceType service)
        external
        onlyGuardianOrOwner
    {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            $.espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, valid, service);
        } else {
            $.espressoNitroTEEVerifier.setEnclaveHash(enclaveHash, valid, service);
        }
    }

    /**
     * @notice Allows the owner to delete enclave hashes
     * @dev Deletion is irreversible, so it requires stricter governance than setting hashes (onlyOwner, not onlyGuardianOrOwner)
     * @param enclaveHashes The list of enclave hashes to delete
     * @param teeType The type of TEE
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(
        bytes32[] memory enclaveHashes,
        TeeType teeType,
        ServiceType service
    ) external onlyOwner {
        EspressoTEEVerifierStorage storage $ = _layout();
        if (teeType == TeeType.SGX) {
            $.espressoSGXTEEVerifier.deleteEnclaveHashes(enclaveHashes, service);
        } else {
            $.espressoNitroTEEVerifier.deleteEnclaveHashes(enclaveHashes, service);
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
        _layout().espressoNitroTEEVerifier.setNitroEnclaveVerifier(nitroVerifier);
    }

    /**
     * @notice Get the EspressoSGXTEEVerifier address
     * @return The EspressoSGXTEEVerifier interface
     */
    function espressoSGXTEEVerifier() external view returns (IEspressoSGXTEEVerifier) {
        return _layout().espressoSGXTEEVerifier;
    }

    /**
     * @notice Get the EspressoNitroTEEVerifier address
     * @return The EspressoNitroTEEVerifier interface
     */
    function espressoNitroTEEVerifier() external view returns (IEspressoNitroTEEVerifier) {
        return _layout().espressoNitroTEEVerifier;
    }
}
