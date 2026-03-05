// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {TEEHelper} from "../src/TEEHelper.sol";
import {ServiceType} from "../src/types/Types.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";

contract TEEHelperImplementation is TEEHelper {
    constructor(address teeVerifier_) {
        __TEEHelper_init(teeVerifier_);
    }
}

contract TEEHelperTest is Test {
    address initialTEEVerifier = address(0xBEEF);
    address rando = address(0xBAD);

    TEEHelperImplementation helper;

    function setUp() public {
        helper = new TEEHelperImplementation(initialTEEVerifier);
    }

    function testOnlyTEEVerifierCanSetEnclaveHash() public {
        vm.prank(initialTEEVerifier);
        helper.setEnclaveHash(bytes32(uint256(1)), true, ServiceType.BatchPoster);
        assertTrue(helper.registeredEnclaveHash(bytes32(uint256(1)), ServiceType.BatchPoster));

        vm.prank(rando);
        vm.expectRevert(abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, rando));
        helper.setEnclaveHash(bytes32(uint256(2)), true, ServiceType.BatchPoster);
    }

    function testInitializeZeroAddressReverts() public {
        vm.expectRevert(ITEEHelper.InvalidTEEVerifierAddress.selector);
        new TEEHelperImplementation(address(0));
    }
}
