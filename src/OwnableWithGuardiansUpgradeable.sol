// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    Ownable2StepUpgradeable
} from "@openzeppelin/contracts-upgradeable-v5/access/Ownable2StepUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable-v5/proxy/utils/Initializable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

// keccak256(abi.encode(uint256(keccak256("espresso.storage.OwnableWithGuardians")) - 1)) & ~bytes32(uint256(0xff))
bytes32 constant OWNABLE_WITH_GUARDIANS_STORAGE_SLOT =
    0x0f4ac8aae5a4fa6a3612928fcd8255b475ff86b500ae30bb272e61542cfc6f00;

/**
 * @title OwnableWithGuardiansUpgradeable
 * @author Espresso Systems (https://espresso.systems)
 * @notice Abstract contract combining Ownable2Step with a guardian role system for emergency operations.
 * @dev This contract provides:
 *      - 2-step ownership transfer (transferOwnership + acceptOwnership)
 *      - Multiple guardian addresses for time-sensitive operations
 *      - TransparentUpgradeableProxy pattern compatibility
 *      - EIP-7201 namespaced storage (via OZ upgradeable contracts)
 *
 * Guardian management is exclusively controlled by the owner. There is no separate
 * role-admin plane; ownership is the single source of authority.
 *
 * Inheriting contracts must:
 *      1. Call __OwnableWithGuardians_init(initialOwner) in their initializer
 */
abstract contract OwnableWithGuardiansUpgradeable is Initializable, Ownable2StepUpgradeable {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @custom:storage-location erc7201:espresso.storage.OwnableWithGuardians
    struct OwnableWithGuardiansStorage {
        EnumerableSet.AddressSet _guardians;
    }

    /// @notice Emitted when a guardian is added
    event GuardianAdded(address indexed guardian);

    /// @notice Emitted when a guardian is removed
    event GuardianRemoved(address indexed guardian);

    /// @notice Error thrown when caller is not a guardian
    error NotGuardian(address caller);

    /// @notice Error thrown when caller is neither guardian nor owner
    error NotGuardianOrOwner(address caller);

    /// @notice Error thrown when trying to add zero address as guardian
    error InvalidGuardianAddress();

    /// @notice Error thrown when trying to add owner as guardian or set guardian as an owner
    error OwnerCantBeGuardian();

    function _getOwnableWithGuardiansStorage()
        private
        pure
        returns (OwnableWithGuardiansStorage storage $)
    {
        assembly {
            $.slot := OWNABLE_WITH_GUARDIANS_STORAGE_SLOT
        }
    }

    /**
     * @dev Initializes the contract with an initial owner.
     * @param initialOwner The address that will be set as the initial owner
     */
    function __OwnableWithGuardians_init(address initialOwner) internal onlyInitializing {
        __Ownable_init(initialOwner);
    }

    /**
     * @notice Modifier that restricts function access to guardian addresses only
     */
    modifier onlyGuardian() {
        if (!_getOwnableWithGuardiansStorage()._guardians.contains(msg.sender)) {
            revert NotGuardian(msg.sender);
        }
        _;
    }

    /**
     * @notice Modifier that restricts function access to either guardian or owner
     * @dev Useful for time-sensitive operations that can be performed by either role
     */
    modifier onlyGuardianOrOwner() {
        if (
            !_getOwnableWithGuardiansStorage()._guardians.contains(msg.sender)
                && msg.sender != owner()
        ) {
            revert NotGuardianOrOwner(msg.sender);
        }
        _;
    }

    /**
     * @notice Adds a new guardian address
     * @dev Only callable by the contract owner. Reverts if guardian is zero address.
     *      No-op if already a guardian.
     * @param guardian The address to grant guardian privileges
     */
    function addGuardian(address guardian) external onlyOwner {
        if (guardian == address(0)) {
            revert InvalidGuardianAddress();
        }
        if (guardian == owner() || guardian == pendingOwner()) {
            revert OwnerCantBeGuardian();
        }
        OwnableWithGuardiansStorage storage $ = _getOwnableWithGuardiansStorage();
        if ($._guardians.add(guardian)) {
            emit GuardianAdded(guardian);
        }
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner. New owner must not be a guardian.
     *
     * Setting `newOwner` to the zero address is allowed; this can be used to cancel an initiated ownership transfer.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        if (_getOwnableWithGuardiansStorage()._guardians.contains(newOwner)) {
            revert OwnerCantBeGuardian();
        }
        super.transferOwnership(newOwner);
    }

    /**
     * @notice Removes a guardian address
     * @dev Only callable by the contract owner. No-op if address is not a guardian.
     * @param guardian The address to revoke guardian privileges from
     */
    function removeGuardian(address guardian) external onlyOwner {
        OwnableWithGuardiansStorage storage $ = _getOwnableWithGuardiansStorage();
        if (!$._guardians.remove(guardian)) {
            return; // Not a guardian, no-op
        }
        emit GuardianRemoved(guardian);
    }

    /**
     * @notice Checks if an address is a guardian
     * @param account The address to check
     * @return bool True if the address is a guardian, false otherwise
     */
    function isGuardian(address account) public view returns (bool) {
        return _getOwnableWithGuardiansStorage()._guardians.contains(account);
    }

    /**
     * @notice Returns all guardian addresses
     * @return address[] Array of all guardian addresses
     */
    function getGuardians() public view returns (address[] memory) {
        return _getOwnableWithGuardiansStorage()._guardians.values();
    }

    /**
     * @notice Returns the total number of guardians
     * @return uint256 The count of guardian addresses
     */
    function guardianCount() public view returns (uint256) {
        return _getOwnableWithGuardiansStorage()._guardians.length();
    }
}
