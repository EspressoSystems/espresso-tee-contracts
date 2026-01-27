// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {TEEHelper} from "../src/TEEHelper.sol";
import {ServiceType} from "../src/types/Types.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";

contract TEEHelperImplementation is TEEHelper {
    function initialize(address teeVerifier_) external initializer {
        __TEEHelper_init(teeVerifier_);
    }
}

contract TEEHelperTest is Test {
    address initialTEEVerifier = address(0xBEEF);
    address rando = address(0xBAD);
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy
    address proxyAdminOwner = address(0xAAA);

    TEEHelperImplementation helper;

    function setUp() public {
        TEEHelperImplementation impl = new TEEHelperImplementation();
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(impl), proxyAdminOwner, "");
        helper = TEEHelperImplementation(address(proxy));
        vm.prank(initialTEEVerifier);
        helper.initialize(initialTEEVerifier);
    }

    function testOnlyTEEVerifierCanSetEnclaveHash() public {
        vm.prank(initialTEEVerifier);
        helper.setEnclaveHash(bytes32(uint256(1)), true, ServiceType.BatchPoster);
        assertTrue(helper.registeredEnclaveHash(bytes32(uint256(1)), ServiceType.BatchPoster));

        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, rando));
        helper.setEnclaveHash(bytes32(uint256(2)), true, ServiceType.BatchPoster);
    }

    function testInitializeCannotRunTwice() public {
        vm.expectRevert(bytes("Initializable: contract is already initialized"));
        helper.initialize(initialTEEVerifier);
    }

    function testInitializeZeroAddressReverts() public {
        TEEHelperImplementation impl = new TEEHelperImplementation();
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(impl), proxyAdminOwner, "");
        TEEHelperImplementation localHelper = TEEHelperImplementation(address(proxy));
        vm.prank(initialTEEVerifier);
        vm.expectRevert(ITEEHelper.InvalidTEEVerifierAddress.selector);
        localHelper.initialize(address(0));
    }
}
