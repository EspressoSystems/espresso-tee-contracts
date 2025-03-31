// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";

contract EspressoSGXTEEVerifierTest is Test {
    address proxyAdmin = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 pcr0Hash = bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(pcr0Hash, new CertManager());
        vm.stopPrank();
    }

    /**
     * Test register signer succeeds upon valid attestation and signature
     */
    function testRegisterSigner() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        espressoNitroTEEVerifier.registerSigner(attestation, signature);
        vm.stopPrank();
    }

    /**
     * Test validate attestation reverts if an invalid signature is passed in
     */
    function testInvalidSignature() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);
        signature[0] = 0x00;

        // Incorrect signature
        vm.expectRevert(bytes("invalid sig"));
        espressoNitroTEEVerifier.registerSigner(attestation, signature);
        vm.stopPrank();
    }

    /**
     * Test validate attestation reverts if an old valid attestation is passed in
     */
    function testOldAttestation() public {
        vm.startPrank(adminTEE);
        vm.warp(1_753_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // Old Attestation, old certificate
        vm.expectRevert(bytes("certificate not valid anymore"));
        espressoNitroTEEVerifier.registerSigner(attestation, signature);
        vm.stopPrank();
    }

    /**
     * Test validate attestation reverts if an invalid attestation prefix is passed in
     */
    function testInvalidAttestionPrefix() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);
        for (uint256 i = 0; i < 5; i++) {
            attestation[i] = 0x00;
        }

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // Invalid prefix
        vm.expectRevert(bytes("invalid attestation prefix"));
        espressoNitroTEEVerifier.registerSigner(attestation, signature);
        vm.stopPrank();
    }
}
