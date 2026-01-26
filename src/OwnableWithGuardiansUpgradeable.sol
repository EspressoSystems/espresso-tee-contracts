// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Ownable2StepUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {AccessControlEnumerableUpgradeable} from
    "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/**
 * @title OwnableWithGuardiansUpgradeable
 * @author Espresso Systems (https://espresso.systems)
 * @notice Abstract contract combining Ownable2Step with a guardian role system for emergency operations.
 * @notice Guardians do not have upgrade permissions unless explicitly granted by overriding _authorizeUpgrade
 * @dev This contract provides:
 *      - 2-step ownership transfer (transferOwnership + acceptOwnership)
 *      - Multiple guardian addresses for time-sensitive operations
 *      - UUPS upgradeability pattern
 *      - EIP-7201 namespaced storage (via OZ upgradeable contracts)
 *
 * Inheriting contracts must:
 *      1. Call __OwnableWithGuardians_init(initialOwner) in their initializer
 *      2. Implement the _authorizeUpgrade function if they want to customize upgrade authorization
 */
abstract contract OwnableWithGuardiansUpgradeable is
    Initializable,
    Ownable2StepUpgradeable,
    AccessControlEnumerableUpgradeable,
    UUPSUpgradeable
{
    /// @notice Role identifier for guardians who can execute time-sensitive operations
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

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

    /**
     * @dev Initializes the contract with an initial owner.
     * @param initialOwner The address that will be set as the initial owner and admin
     */
    function __OwnableWithGuardians_init(address initialOwner) internal onlyInitializing {
        __Ownable_init(initialOwner);
        __AccessControl_init();
        __AccessControlEnumerable_init();
        __UUPSUpgradeable_init();
        __OwnableWithGuardians_init_unchained(initialOwner);
    }

    function __OwnableWithGuardians_init_unchained(address initialOwner)
        internal
        onlyInitializing
    {
        // Grant the initial owner the default admin role for managing guardians
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);

        // Explicitly set DEFAULT_ADMIN_ROLE as the admin of GUARDIAN_ROLE for clarity
        _setRoleAdmin(GUARDIAN_ROLE, DEFAULT_ADMIN_ROLE);
    }

    /**
     * @notice Modifier that restricts function access to guardian addresses only
     */
    modifier onlyGuardian() {
        if (!hasRole(GUARDIAN_ROLE, msg.sender)) {
            revert NotGuardian(msg.sender);
        }
        _;
    }

    /**
     * @notice Modifier that restricts function access to either guardian or owner
     * @dev Useful for time-sensitive operations that can be performed by either role
     */
    modifier onlyGuardianOrOwner() {
        if (!hasRole(GUARDIAN_ROLE, msg.sender) && msg.sender != owner()) {
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
        if (hasRole(GUARDIAN_ROLE, guardian)) {
            return; // Already a guardian, no-op
        }
        grantRole(GUARDIAN_ROLE, guardian);
        emit GuardianAdded(guardian);
    }

    /**
     * @notice Removes a guardian address
     * @dev Only callable by the contract owner. No-op if address is not a guardian.
     * @param guardian The address to revoke guardian privileges from
     */
    function removeGuardian(address guardian) external onlyOwner {
        if (!hasRole(GUARDIAN_ROLE, guardian)) {
            return; // Not a guardian, no-op
        }
        revokeRole(GUARDIAN_ROLE, guardian);
        emit GuardianRemoved(guardian);
    }

    /**
     * @notice Checks if an address is a guardian
     * @param account The address to check
     * @return bool True if the address is a guardian, false otherwise
     */
    function isGuardian(address account) public view returns (bool) {
        return hasRole(GUARDIAN_ROLE, account);
    }

    /**
     * @notice Returns all guardian addresses
     * @return address[] Array of all guardian addresses
     */
    function getGuardians() public view returns (address[] memory) {
        uint256 count = getRoleMemberCount(GUARDIAN_ROLE);
        address[] memory guardians = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            guardians[i] = getRoleMember(GUARDIAN_ROLE, i);
        }
        return guardians;
    }

    /**
     * @notice Returns the total number of guardians
     * @return uint256 The count of guardian addresses
     */
    function guardianCount() public view returns (uint256) {
        return getRoleMemberCount(GUARDIAN_ROLE);
    }

    /**
     * @dev Override required by Solidity for multiple inheritance
     * @notice Ensures owner retains admin role even after ownership transfer
     */
    function _transferOwnership(address newOwner) internal virtual override {
        address previousOwner = owner();
        super._transferOwnership(newOwner);

        // Transfer admin role to new owner
        if (previousOwner != address(0)) {
            _revokeRole(DEFAULT_ADMIN_ROLE, previousOwner);
        }
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract.
     * @param newImplementation The address of the new implementation
     *
     * By default, only the owner can authorize upgrades. Override this function to customize authorization.
     */
    function _authorizeUpgrade(address newImplementation) internal virtual override onlyOwner {}
}
