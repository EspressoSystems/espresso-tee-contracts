// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {OwnableWithGuardiansUpgradeable} from "../src/OwnableWithGuardiansUpgradeable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {
    ITransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title MockGuardedContract
 * @notice Concrete implementation of OwnableWithGuardiansUpgradeable for testing
 */
contract MockGuardedContract is OwnableWithGuardiansUpgradeable {
    uint256 public value;
    uint256 public emergencyValue;

    function initialize(address initialOwner) public initializer {
        __OwnableWithGuardians_init(initialOwner);
    }

    function ownerOnlyFunction() external onlyOwner {
        value = 100;
    }

    function guardianOnlyFunction() external onlyGuardian {
        value = 200;
    }

    function guardianOrOwnerFunction() external onlyGuardianOrOwner {
        emergencyValue = 300;
    }

    function publicFunction() external {
        value = 400;
    }
}

/**
 * @title MockGuardedContractV2
 * @notice Upgraded version for testing TransparentUpgradeableProxy upgradeability
 */
contract MockGuardedContractV2 is OwnableWithGuardiansUpgradeable {
    uint256 public value;
    uint256 public emergencyValue;
    uint256 public newValue; // New field in V2

    function initialize(address initialOwner) public initializer {
        __OwnableWithGuardians_init(initialOwner);
    }

    function ownerOnlyFunction() external onlyOwner {
        value = 100;
    }

    function guardianOnlyFunction() external onlyGuardian {
        value = 200;
    }

    function guardianOrOwnerFunction() external onlyGuardianOrOwner {
        emergencyValue = 300;
    }

    function publicFunction() external {
        value = 400;
    }

    // New function in V2
    function newFunction() external {
        newValue = 999;
    }
}

contract OwnableWithGuardiansUpgradeableTest is Test {
    MockGuardedContract public implementation;
    MockGuardedContract public proxy;
    ProxyAdmin public proxyAdmin;
    TransparentUpgradeableProxy public transparentProxy;

    address public owner = address(0x1);
    address public guardian1 = address(0x2);
    address public guardian2 = address(0x3);
    address public user = address(0x4);
    address public newOwner = address(0x5);
    address public proxyAdminOwner = address(0x6);

    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        // Deploy implementation
        implementation = new MockGuardedContract();

        // Deploy ProxyAdmin
        vm.prank(proxyAdminOwner);
        proxyAdmin = new ProxyAdmin(proxyAdminOwner);

        // Deploy proxy and initialize
        bytes memory initData =
            abi.encodeWithSelector(MockGuardedContract.initialize.selector, owner);
        transparentProxy =
            new TransparentUpgradeableProxy(address(implementation), address(proxyAdmin), initData);
        proxy = MockGuardedContract(address(transparentProxy));
    }

    // ============ Initialization Tests ============

    function testInitialization() public view {
        assertEq(proxy.owner(), owner);
        assertEq(proxy.guardianCount(), 0);
        assertTrue(proxy.hasRole(proxy.DEFAULT_ADMIN_ROLE(), owner));
    }

    function testCannotReinitialize() public {
        vm.expectRevert();
        proxy.initialize(address(0x999));
    }

    // ============ Guardian Management Tests ============

    function testAddGuardian() public {
        vm.startPrank(owner);

        vm.expectEmit(true, false, false, false);
        emit GuardianAdded(guardian1);
        proxy.addGuardian(guardian1);

        assertTrue(proxy.isGuardian(guardian1));
        assertEq(proxy.guardianCount(), 1);

        address[] memory guardians = proxy.getGuardians();
        assertEq(guardians.length, 1);
        assertEq(guardians[0], guardian1);

        vm.stopPrank();
    }

    function testAddMultipleGuardians() public {
        vm.startPrank(owner);

        proxy.addGuardian(guardian1);
        proxy.addGuardian(guardian2);

        assertEq(proxy.guardianCount(), 2);
        assertTrue(proxy.isGuardian(guardian1));
        assertTrue(proxy.isGuardian(guardian2));

        address[] memory guardians = proxy.getGuardians();
        assertEq(guardians.length, 2);

        vm.stopPrank();
    }

    function testRemoveGuardian() public {
        vm.startPrank(owner);

        proxy.addGuardian(guardian1);
        assertTrue(proxy.isGuardian(guardian1));

        vm.expectEmit(true, false, false, false);
        emit GuardianRemoved(guardian1);
        proxy.removeGuardian(guardian1);

        assertFalse(proxy.isGuardian(guardian1));
        assertEq(proxy.guardianCount(), 0);

        vm.stopPrank();
    }

    function testOnlyOwnerCanAddGuardian() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proxy.addGuardian(guardian1);
    }

    function testOnlyOwnerCanRemoveGuardian() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proxy.removeGuardian(guardian1);
    }

    function testGuardianCannotAddOtherGuardians() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(guardian1);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, guardian1)
        );
        proxy.addGuardian(guardian2);
    }

    // ============ Access Control Tests ============

    function testOwnerOnlyFunction() public {
        vm.prank(owner);
        proxy.ownerOnlyFunction();
        assertEq(proxy.value(), 100);
    }

    function testOwnerOnlyFunctionRevertsForNonOwner() public {
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proxy.ownerOnlyFunction();
    }

    function testOwnerOnlyFunctionRevertsForGuardian() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(guardian1);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, guardian1)
        );
        proxy.ownerOnlyFunction();
    }

    function testGuardianOnlyFunction() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(guardian1);
        proxy.guardianOnlyFunction();
        assertEq(proxy.value(), 200);
    }

    function testGuardianOnlyFunctionRevertsForNonGuardian() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableWithGuardiansUpgradeable.NotGuardian.selector, user)
        );
        proxy.guardianOnlyFunction();
    }

    function testGuardianOnlyFunctionRevertsForOwner() public {
        vm.prank(owner);
        vm.expectRevert(
            abi.encodeWithSelector(OwnableWithGuardiansUpgradeable.NotGuardian.selector, owner)
        );
        proxy.guardianOnlyFunction();
    }

    function testGuardianOrOwnerFunctionAsOwner() public {
        vm.prank(owner);
        proxy.guardianOrOwnerFunction();
        assertEq(proxy.emergencyValue(), 300);
    }

    function testGuardianOrOwnerFunctionAsGuardian() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(guardian1);
        proxy.guardianOrOwnerFunction();
        assertEq(proxy.emergencyValue(), 300);
    }

    function testGuardianOrOwnerFunctionRevertsForUser() public {
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableWithGuardiansUpgradeable.NotGuardianOrOwner.selector, user
            )
        );
        proxy.guardianOrOwnerFunction();
    }

    // ============ Ownership Transfer Tests ============

    function testTransferOwnership() public {
        vm.startPrank(owner);

        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferStarted(owner, newOwner);
        proxy.transferOwnership(newOwner);

        assertEq(proxy.pendingOwner(), newOwner);
        assertEq(proxy.owner(), owner); // Still old owner until accepted

        vm.stopPrank();

        vm.startPrank(newOwner);

        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        proxy.acceptOwnership();

        assertEq(proxy.owner(), newOwner);
        assertEq(proxy.pendingOwner(), address(0));
        assertTrue(proxy.hasRole(proxy.DEFAULT_ADMIN_ROLE(), newOwner));
        assertFalse(proxy.hasRole(proxy.DEFAULT_ADMIN_ROLE(), owner));

        vm.stopPrank();
    }

    function testNewOwnerCanManageGuardians() public {
        // Transfer ownership
        vm.prank(owner);
        proxy.transferOwnership(newOwner);

        vm.prank(newOwner);
        proxy.acceptOwnership();

        // New owner should be able to add guardians
        vm.prank(newOwner);
        proxy.addGuardian(guardian1);

        assertTrue(proxy.isGuardian(guardian1));
    }

    function testOldOwnerCannotManageGuardiansAfterTransfer() public {
        // Transfer ownership
        vm.prank(owner);
        proxy.transferOwnership(newOwner);

        vm.prank(newOwner);
        proxy.acceptOwnership();

        // Old owner should not be able to add guardians
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        proxy.addGuardian(guardian1);
    }

    function testRenounceOwnership() public {
        vm.prank(owner);
        proxy.renounceOwnership();

        assertEq(proxy.owner(), address(0));
        assertFalse(proxy.hasRole(proxy.DEFAULT_ADMIN_ROLE(), owner));
    }

    // ============ Upgradeability Tests ============

    function testUpgradeAsOwner() public {
        MockGuardedContractV2 newImplementation = new MockGuardedContractV2();

        vm.prank(proxyAdminOwner);
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(transparentProxy)), address(newImplementation), ""
        );

        // Test that upgrade worked
        MockGuardedContractV2 upgradedProxy = MockGuardedContractV2(address(proxy));
        upgradedProxy.newFunction();
        assertEq(upgradedProxy.newValue(), 999);

        // Test that state is preserved
        assertEq(upgradedProxy.owner(), owner);
    }

    function testUpgradeRevertsForNonOwner() public {
        MockGuardedContractV2 newImplementation = new MockGuardedContractV2();

        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(transparentProxy)), address(newImplementation), ""
        );
    }

    function testUpgradeRevertsForGuardian() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        MockGuardedContractV2 newImplementation = new MockGuardedContractV2();

        vm.prank(guardian1);
        vm.expectRevert(
            abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, guardian1)
        );
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(transparentProxy)), address(newImplementation), ""
        );
    }

    function testGuardiansPreservedAfterUpgrade() public {
        // Add guardians
        vm.startPrank(owner);
        proxy.addGuardian(guardian1);
        proxy.addGuardian(guardian2);
        vm.stopPrank();

        // Upgrade
        MockGuardedContractV2 newImplementation = new MockGuardedContractV2();
        vm.prank(proxyAdminOwner);
        proxyAdmin.upgradeAndCall(
            ITransparentUpgradeableProxy(address(transparentProxy)), address(newImplementation), ""
        );

        // Check guardians are preserved
        MockGuardedContractV2 upgradedProxy = MockGuardedContractV2(address(proxy));
        assertEq(upgradedProxy.guardianCount(), 2);
        assertTrue(upgradedProxy.isGuardian(guardian1));
        assertTrue(upgradedProxy.isGuardian(guardian2));
    }

    // ============ Edge Cases ============

    function testGetGuardiansWhenEmpty() public view {
        address[] memory guardians = proxy.getGuardians();
        assertEq(guardians.length, 0);
    }

    function testIsGuardianReturnsFalseForNonGuardian() public view {
        assertFalse(proxy.isGuardian(user));
    }

    function testAddSameGuardianTwice() public {
        vm.startPrank(owner);
        proxy.addGuardian(guardian1);

        // Adding the same guardian again should not increase count or emit event
        proxy.addGuardian(guardian1);

        // Count should still be 1
        assertEq(proxy.guardianCount(), 1);
        vm.stopPrank();
    }

    function testRemoveNonGuardian() public {
        vm.prank(owner);
        // Removing non-guardian should be a no-op (no revert, no event)
        proxy.removeGuardian(guardian1);

        assertEq(proxy.guardianCount(), 0);
    }

    function testAddZeroAddressAsGuardian() public {
        vm.prank(owner);
        vm.expectRevert(OwnableWithGuardiansUpgradeable.InvalidGuardianAddress.selector);
        proxy.addGuardian(address(0));
    }

    function testCanAddManyGuardians() public {
        vm.startPrank(owner);

        // Add 50 guardians - no limit
        for (uint160 i = 1; i <= 50; i++) {
            proxy.addGuardian(address(i));
        }

        assertEq(proxy.guardianCount(), 50);

        // getGuardians() should still work (though may be gas-intensive)
        address[] memory guardians = proxy.getGuardians();
        assertEq(guardians.length, 50);
        assertEq(guardians[0], address(1));
        assertEq(guardians[49], address(50));

        vm.stopPrank();
    }

    function testRenounceOwnershipPreventsGuardianManagement() public {
        vm.startPrank(owner);
        proxy.addGuardian(guardian1);
        proxy.renounceOwnership();
        vm.stopPrank();

        // No owner, so can't add/remove guardians
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        vm.prank(owner);
        proxy.addGuardian(guardian2);
    }

    function testGuardianOperationsStillWorkAfterOwnershipRenounced() public {
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(owner);
        proxy.renounceOwnership();

        // Guardian should still be able to call guardian functions
        vm.prank(guardian1);
        proxy.guardianOnlyFunction();
        assertEq(proxy.value(), 200);
    }

    function testDirectAdminRoleManipulationIsNotAllowed() public {
        bytes32 adminRole = proxy.DEFAULT_ADMIN_ROLE();

        // Non-admin user cannot grant admin role
        vm.prank(user);
        vm.expectRevert();
        proxy.grantRole(adminRole, user);

        // Guardian can't grant admin role either
        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.prank(guardian1);
        vm.expectRevert();
        proxy.grantRole(adminRole, guardian1);

        // Only current admin (owner) can grant admin role
        vm.prank(owner);
        proxy.grantRole(adminRole, newOwner);
        assertTrue(proxy.hasRole(adminRole, newOwner));
    }

    function testDirectGuardianRoleManipulationViaAccessControl() public {
        bytes32 guardianRole = proxy.GUARDIAN_ROLE();
        bytes32 adminRole = proxy.DEFAULT_ADMIN_ROLE();

        // Owner (who has admin role) can use AccessControl's grantRole directly
        vm.prank(owner);
        proxy.grantRole(guardianRole, guardian1);
        assertTrue(proxy.isGuardian(guardian1));

        // Non-admin cannot grant guardian role - must use proper error encoding
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                bytes4(keccak256("AccessControlUnauthorizedAccount(address,bytes32)")),
                user,
                adminRole
            )
        );
        proxy.grantRole(guardianRole, guardian2);
    }

    // ============ Fuzz Tests ============

    function testFuzz_AddGuardian(address guardian) public {
        vm.assume(guardian != address(0));
        vm.assume(guardian != owner);

        vm.prank(owner);
        proxy.addGuardian(guardian);

        assertTrue(proxy.isGuardian(guardian));
        assertEq(proxy.guardianCount(), 1);
    }

    function testFuzz_RemoveGuardian(address guardian) public {
        vm.assume(guardian != address(0));
        vm.assume(guardian != owner);

        vm.startPrank(owner);
        proxy.addGuardian(guardian);
        assertTrue(proxy.isGuardian(guardian));

        proxy.removeGuardian(guardian);
        assertFalse(proxy.isGuardian(guardian));
        assertEq(proxy.guardianCount(), 0);
        vm.stopPrank();
    }

    function testFuzz_GuardianCanCallGuardianFunction(address guardian) public {
        vm.assume(guardian != address(0));
        vm.assume(guardian != owner);

        vm.prank(owner);
        proxy.addGuardian(guardian);

        vm.prank(guardian);
        proxy.guardianOnlyFunction();
        assertEq(proxy.value(), 200);
    }

    function testFuzz_NonGuardianCannotCallGuardianFunction(address notGuardian) public {
        vm.assume(notGuardian != address(0));
        vm.assume(notGuardian != owner);

        vm.prank(owner);
        proxy.addGuardian(guardian1);

        vm.assume(notGuardian != guardian1);

        vm.prank(notGuardian);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableWithGuardiansUpgradeable.NotGuardian.selector, notGuardian
            )
        );
        proxy.guardianOnlyFunction();
    }
}
