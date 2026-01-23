// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ServiceType} from "./types/Types.sol";
import "./interface/ITEEHelper.sol";

abstract contract TEEHelper is ITEEHelper, Initializable {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct TEEHelperStorage {
        mapping(ServiceType => mapping(bytes32 enclaveHash => bool valid)) registeredEnclaveHashes;
        mapping(ServiceType => mapping(address signer => bool valid)) registeredServices;
        mapping(
            ServiceType => mapping(bytes32 enclaveHash => EnumerableSet.AddressSet signers)
        ) enclaveHashToSigner;
        address teeVerifier;
    }

    // keccak256(abi.encode(uint256(keccak256("espresso.storage.TEEHelper")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant TEE_HELPER_STORAGE_SLOT =
        0x6c53fdf1cef7bc567e8d46761d9c42d29c5fad7063be8d47b686412bfc375800;

    function _layout() internal pure returns (TEEHelperStorage storage l) {
        bytes32 slot = TEE_HELPER_STORAGE_SLOT;
        assembly {
            l.slot := slot
        }
    }

    modifier onlyTEEVerifier() {
        if (msg.sender != teeVerifier()) {
            revert UnauthorizedTEEVerifier(msg.sender);
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function __TEEHelper_init(address teeVerifier_) internal onlyInitializing {
        _setTEEVerifier(teeVerifier_);
    }

    function teeVerifier() public view returns (address) {
        return _layout().teeVerifier;
    }

    /**
     * @notice Allows the tee verifier to set the enclave hash, setting valid to true will allow any enclave
     * with a valid pcr0 hash to register a signer (address which was generated inside the TEE). Setting valid to false
     * will further remove the enclave hash from the registered enclave hash list thus preventing any enclave with the given
     * hash from registering a signer.
     * @param enclaveHash The hash of the enclave
     * @param valid Whether the enclave hash is valid or not
     * @param service The service type (BatchPoster or CaffNode)
     */
    function setEnclaveHash(bytes32 enclaveHash, bool valid, ServiceType service)
        external
        virtual
        onlyTEEVerifier
    {
        _layout().registeredEnclaveHashes[service][enclaveHash] = valid;
        emit EnclaveHashSet(enclaveHash, valid, service);
    }

    /**
     * @notice This function retrieves whether a signer is registered or not
     * @param signer The address of the signer
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the signer is registered, false otherwise
     */
    function registeredService(address signer, ServiceType service)
        external
        view
        virtual
        returns (bool)
    {
        return _layout().registeredServices[service][signer];
    }

    /**
     * @notice This function retrieves whether an enclave hash is registered or not
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return bool True if the enclave hash is registered, false otherwise
     */
    function registeredEnclaveHash(bytes32 enclaveHash, ServiceType service)
        external
        view
        virtual
        returns (bool)
    {
        return _layout().registeredEnclaveHashes[service][enclaveHash];
    }

    /**
     * @notice This function retrieves the list of signers registered for a given enclave hash
     * @param enclaveHash The hash of the enclave
     * @param service The service type (BatchPoster or CaffNode)
     * @return address[] The list of signers registered for the given enclave hash
     */
    function enclaveHashSigners(bytes32 enclaveHash, ServiceType service)
        external
        view
        virtual
        returns (address[] memory)
    {
        EnumerableSet.AddressSet storage signersSet =
            _layout().enclaveHashToSigner[service][enclaveHash];
        return signersSet.values();
    }

    /**
     * @notice Allows the tee verifier to delete registered enclave hashes from the list of valid enclave hashes
     * @param enclaveHashes The list of enclave hashes to be deleted
     * @param service The service type (BatchPoster or CaffNode)
     */
    function deleteEnclaveHashes(bytes32[] memory enclaveHashes, ServiceType service)
        external
        virtual
        onlyTEEVerifier
    {
        TEEHelperStorage storage $ = _layout();
        for (uint256 i = 0; i < enclaveHashes.length; i++) {
            // also delete all the corresponding signers from registeredService mapping
            EnumerableSet.AddressSet storage signersSet =
                $.enclaveHashToSigner[service][enclaveHashes[i]];
            while (signersSet.length() > 0) {
                address signer = signersSet.at(0);
                delete $.registeredServices[service][signer];
                // slither-disable-next-line unused-return
                signersSet.remove(signer);
                emit DeletedRegisteredService(signer, service);
            }
            delete $.registeredEnclaveHashes[service][enclaveHashes[i]];
            emit DeletedEnclaveHash(enclaveHashes[i], service);
        }
    }

    function _setTEEVerifier(address newTEEVerifier) internal {
        if (newTEEVerifier == address(0)) {
            revert InvalidTEEVerifierAddress();
        }
        _layout().teeVerifier = newTEEVerifier;
        emit TeeVerifierSet(newTEEVerifier);
    }
}
