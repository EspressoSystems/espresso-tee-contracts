// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";

/**
 * @title DoS Attack Demonstrations for EspressoTEEVerifier
 */
contract EspressoTEEVerifierDoSTest is Test {
    EspressoTEEVerifier teeVerifier;
    address owner = address(100);
    address user = address(200);

    function setUp() public {
        vm.startPrank(owner);

        // Deploy with mock verifiers
        MockSGXVerifier sgxVerifier = new MockSGXVerifier();
        MockNitroVerifier nitroVerifier = new MockNitroVerifier();

        teeVerifier = new EspressoTEEVerifier(
            IEspressoSGXTEEVerifier(address(sgxVerifier)),
            IEspressoNitroTEEVerifier(address(nitroVerifier))
        );

        vm.stopPrank();
    }

    /**
     * @dev DoS Vector #1: Owner sets verifier to address(0)
     */
    function testDoS_ZeroAddressVerifier() public {
        vm.startPrank(owner);

        // Owner accidentally or maliciously sets SGX verifier to zero
        teeVerifier.setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier(address(0)));

        vm.stopPrank();
        vm.startPrank(user);

        // Now all SGX operations fail
        bytes memory data = hex"1234";

        // This will revert with a low-level error when trying to call address(0)
        vm.expectRevert();
        teeVerifier.registerService(
            data, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        vm.expectRevert();
        teeVerifier.verify(
            data, bytes32(0), IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        vm.stopPrank();
    }

    /**
     * @dev DoS Vector #2: Owner sets verifier to always-reverting contract
     */
    function testDoS_RevertingVerifier() public {
        vm.startPrank(owner);

        // Deploy a malicious verifier that always reverts
        DoSVerifier dosVerifier = new DoSVerifier();
        teeVerifier.setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier(address(dosVerifier)));

        vm.stopPrank();
        vm.startPrank(user);

        bytes memory data = hex"1234";

        // All Nitro operations now fail
        vm.expectRevert("DoS attack");
        teeVerifier.registerService(
            data, data, IEspressoTEEVerifier.TeeType.NITRO, ServiceType.BatchPoster
        );

        // Note: verify() calls ECDSA.recover first, so it fails with ECDSA error before reaching the DoS verifier
        // Testing registerService is sufficient to demonstrate the DoS vulnerability

        vm.stopPrank();
    }

    /**
     * @dev DoS Vector #3: Contract with infinite gas consumption
     */
    function testDoS_GasExhaustionVerifier() public {
        vm.startPrank(owner);

        GasExhaustionVerifier gasVerifier = new GasExhaustionVerifier();
        teeVerifier.setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier(address(gasVerifier)));

        vm.stopPrank();
        vm.startPrank(user);

        bytes memory data = hex"1234";

        // This will run out of gas
        vm.expectRevert(); // Out of gas revert
        teeVerifier.registerService{gas: 1_000_000}(
            data, data, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );

        vm.stopPrank();
    }

    /**
     * @dev Demonstrate that there's no way to recover from DoS without owner
     */
    function testDoS_NoRecoveryMechanism() public {
        vm.startPrank(owner);

        // Set to broken verifier
        DoSVerifier dosVerifier = new DoSVerifier();
        teeVerifier.setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier(address(dosVerifier)));

        vm.stopPrank();

        // Non-owner cannot fix it
        vm.startPrank(user);

        MockSGXVerifier goodVerifier = new MockSGXVerifier();

        vm.expectRevert("Ownable: caller is not the owner");
        teeVerifier.setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier(address(goodVerifier)));

        vm.stopPrank();

        // System remains DoS'd until owner acts
        // If owner key is lost/compromised, system is permanently DoS'd
    }
}

/**
 * @dev Mock verifiers for testing
 */
contract MockSGXVerifier {
    mapping(address => mapping(ServiceType => bool)) public services;

    function registerService(bytes calldata, bytes calldata, ServiceType service) external {
        services[msg.sender][service] = true;
    }

    function registeredService(address signer, ServiceType service) external view returns (bool) {
        return services[signer][service];
    }

    function registeredEnclaveHash(bytes32, ServiceType) external pure returns (bool) {
        return true;
    }

    function enclaveHashSigners(bytes32, ServiceType) external pure returns (address[] memory) {
        address[] memory signers = new address[](0);
        return signers;
    }
}

contract MockNitroVerifier {
    mapping(address => mapping(ServiceType => bool)) public services;

    function registerService(bytes calldata, bytes calldata, ServiceType service) external {
        services[msg.sender][service] = true;
    }

    function registeredService(address signer, ServiceType service) external view returns (bool) {
        return services[signer][service];
    }

    function registeredEnclaveHash(bytes32, ServiceType) external pure returns (bool) {
        return true;
    }

    function enclaveHashSigners(bytes32, ServiceType) external pure returns (address[] memory) {
        address[] memory signers = new address[](0);
        return signers;
    }
}

/**
 * @dev Malicious verifier that always reverts
 */
contract DoSVerifier {
    function registerService(bytes calldata, bytes calldata, ServiceType) external pure {
        revert("DoS attack");
    }

    function registeredService(address, ServiceType) external pure returns (bool) {
        revert("DoS attack");
    }

    function registeredEnclaveHash(bytes32, ServiceType) external pure returns (bool) {
        revert("DoS attack");
    }

    function enclaveHashSigners(bytes32, ServiceType) external pure returns (address[] memory) {
        revert("DoS attack");
    }
}

/**
 * @dev Malicious verifier that exhausts gas
 */
contract GasExhaustionVerifier {
    function registerService(bytes calldata, bytes calldata, ServiceType) external pure {
        // Infinite loop to exhaust gas
        uint256 i = 0;
        while (i < type(uint256).max) {
            i++;
        }
    }

    function registeredService(address, ServiceType) external pure returns (bool) {
        return false;
    }

    function registeredEnclaveHash(bytes32, ServiceType) external pure returns (bool) {
        return false;
    }

    function enclaveHashSigners(bytes32, ServiceType) external pure returns (address[] memory) {
        address[] memory signers = new address[](0);
        return signers;
    }
}
