// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {OwnableWithGuardiansUpgradeable} from "./OwnableWithGuardiansUpgradeable.sol";
import {IEspressoNitroTEEVerifier} from "./interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "./interface/IEspressoTEEVerifier.sol";
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
        IEspressoNitroTEEVerifier espressoNitroTEEVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.EspressoTEEVerifier")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant ESPRESSO_TEE_VERIFIER_STORAGE_SLOT =
        0x89639f446056f5d7661bbd94e8ab0617a80058ed7b072845818d4b93332e4800;

    bytes32 private constant ESPRESSO_TEE_VERIFIER_TYPE_HASH =
        keccak256("EspressoTEEVerifier(bytes32 commitment)");

    function _requireNitroTeeType(TeeType teeType) private pure {
        if (teeType != TeeType.NITRO) {
            revert UnsupportedTeeType(teeType);
        }
    }

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
     * @param _espressoNitroTEEVerifier The Nitro verifier used for Nitro-based attestations.
     */
    function initialize(address _owner, IEspressoNitroTEEVerifier _espressoNitroTEEVerifier)
        public
        initializer
    {
        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoNitroTEEVerifier = _espressoNitroTEEVerifier;
        __OwnableWithGuardians_init(_owner);
        __EIP712_init("EspressoTEEVerifier", "1");
    }

    /**
     * @notice This function is used to verify the signature of the user data
     * @param signature The signature of the user data
     * @param userDataHash The hash of the user data
     * @param teeType The type of TEE
     */
    function verify(bytes memory signature, bytes32 userDataHash, TeeType teeType)
        external
        view
        returns (bool)
    {
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        bytes32 structHash = keccak256(abi.encode(ESPRESSO_TEE_VERIFIER_TYPE_HASH, userDataHash));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        // Use isSignerValid to check both registration AND hash validity
        if (!$.espressoNitroTEEVerifier.isSignerValid(signer)) {
            revert InvalidSignature();
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
     */
    function registerService(bytes calldata verificationData, bytes calldata data, TeeType teeType)
        external
    {
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoNitroTEEVerifier.registerService(verificationData, data);
    }

    /**
     * @notice This function checks if a signer is valid for a given TEE type
     * @param signer The address of the signer
     * @param teeType The type of TEE
     */
    function isSignerValid(address signer, TeeType teeType) external view returns (bool) {
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        return $.espressoNitroTEEVerifier.isSignerValid(signer);
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
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        return $.espressoNitroTEEVerifier.registeredEnclaveHash(enclaveHash);
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
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, TeeType teeType)
        external
        onlyGuardianOrOwner
    {
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoNitroTEEVerifier.setEnclaveHash(enclaveHash, valid);
    }

    /**
     * @notice Allows the owner to delete enclave hashes
     * @dev Deleting a hash breaks services that are using it, so it requires stricter governance than setting hashes (onlyOwner, not onlyGuardianOrOwner)
     * @param enclaveHashes The list of enclave hashes to delete
     * @param teeType The type of TEE
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, TeeType teeType)
        external
        onlyOwner
    {
        _requireNitroTeeType(teeType);

        EspressoTEEVerifierStorage storage $ = _layout();
        $.espressoNitroTEEVerifier.deleteEnclaveHashes(enclaveHashes);
    }

    /**
     * @notice Set the nitro enclave verifier for Nitro TEEs
     * @param nitroVerifier The address of the nitro enclave verifier
     */
    function setNitroEnclaveVerifier(address nitroVerifier) external onlyOwner {
        _layout().espressoNitroTEEVerifier.setNitroEnclaveVerifier(nitroVerifier);
    }

    /**
     * @notice Get the EspressoNitroTEEVerifier address
     * @return The EspressoNitroTEEVerifier interface
     */
    function espressoNitroTEEVerifier() external view returns (IEspressoNitroTEEVerifier) {
        return _layout().espressoNitroTEEVerifier;
    }
}
