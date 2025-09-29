// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";
import {ServiceType} from "../src/types/Types.sol";

contract EspressoNitroTEEVerifierTest is Test {
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
    function testRegisterBatchPoster() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
        vm.stopPrank();
    }

    /**
     * Test register signer succeeds upon valid attestation and signature
     */
    function testRegisterBatchPosterWithIndefiniteItemLengthAttestation() public {
        vm.startPrank(adminTEE);
        vm.warp(1_751_035_200);
        string memory attestationPath = "/test/configs/indefinite-item-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/indefinite-item-sig.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
        vm.stopPrank();
    }

    /**
     * Test register signer fails upon invalid attestation pcr0
     */
    function testRegisterBatchPosterInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), false);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector,
                pcr0Hash,
                ServiceType.BatchPoster
            )
        );
        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
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
        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
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
        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
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
        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
    function testNitroOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoNitroTEEVerifier.owner()), adminTEE);
        espressoNitroTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoNitroTEEVerifier.acceptOwnership();
        assertEq(address(espressoNitroTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    // Test transfer Ownership failure
    function testNitroOwnershipTransferFailure() public {
        vm.startPrank(fakeAddress);
        assertEq(address(espressoNitroTEEVerifier.owner()), adminTEE);
        vm.expectRevert(bytes("Ownable: caller is not the owner"));
        espressoNitroTEEVerifier.transferOwnership(address(150));
    }

    // Test setting Enclave hash for owner and non-owner
    function testSetNitroEnclaveHash() public {
        vm.startPrank(adminTEE);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), true);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false, ServiceType.BatchPoster);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosterEnclaveHashes(pcr0Hash), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * Test we can delete a registered signer with only the correct admin address
     */
    function testDeleteRegisterBatchPosterOwnership() public {
        // register signer
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // register and verify signer exists
        espressoNitroTEEVerifier.registerBatchPoster(attestation, signature);
        bytes memory pubKey =
            hex"090e39a638094d9805b89a831b7e710db345e701bb0e9865a60b6b50089b3f4b89c168fbf2219ba79b6e86eb63decac3be0dd3e8fb4c0f1b39d4ecd4589704ff";
        address signer = address(uint160(uint256(keccak256(pubKey))));
        assertEq(espressoNitroTEEVerifier.registeredBatchPosters(signer), true);

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        address[] memory signersToDelete = new address[](1);
        signersToDelete[0] = signer;

        // verify we cant delete
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.deleteRegisteredBatchPosters(signersToDelete);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete and verify signer address is gone
        espressoNitroTEEVerifier.deleteRegisteredBatchPosters(signersToDelete);
        assertEq(espressoNitroTEEVerifier.registeredBatchPosters(signer), false);
    }

    function testVerifyCertParentCertNotVerified() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        string memory certPath = "/test/configs/unverified-cert.bin";
        string memory certFile = string.concat(vm.projectRoot(), certPath);
        bytes memory certificate = vm.readFileBinary(certFile);

        string memory parentCertHashPath = "/test/configs/unverified-parent-cert-hash.bin";
        string memory parentCertHashFile = string.concat(vm.projectRoot(), parentCertHashPath);
        bytes32 parentCertHash = bytes32(vm.readFileBinary(parentCertHashFile));
        bytes32 certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);

        vm.expectRevert("parent cert unverified");
        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        vm.stopPrank();
    }

    function testVerifyCert() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        string memory certPath = "/test/configs/verified-cert.bin";
        string memory certFile = string.concat(vm.projectRoot(), certPath);
        bytes memory certificate = vm.readFileBinary(certFile);

        string memory parentCertHashPath = "/test/configs/verified-parent-cert-hash.bin";
        string memory parentCertHashFile = string.concat(vm.projectRoot(), parentCertHashPath);
        bytes32 parentCertHash = bytes32(vm.readFileBinary(parentCertHashFile));
        bytes32 certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);

        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
        vm.stopPrank();
    }

    // Test verification of full certificate chain
    function testVerifyCertChain() public {
        vm.startPrank(adminTEE);
        vm.warp(1_745_596_800);

        string memory certPath = "/test/configs/certs/ca0cert.bin";
        string memory certFile = string.concat(vm.projectRoot(), certPath);
        bytes memory certificate = vm.readFileBinary(certFile);
        bytes32 parentCertHash = keccak256(certificate);

        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(parentCertHash), true);

        certPath = "/test/configs/certs/ca1cert.bin";
        certFile = string.concat(vm.projectRoot(), certPath);
        certificate = vm.readFileBinary(certFile);
        bytes32 certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
        parentCertHash = certHash;

        certPath = "/test/configs/certs/ca2cert.bin";
        certFile = string.concat(vm.projectRoot(), certPath);
        certificate = vm.readFileBinary(certFile);
        certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
        parentCertHash = certHash;

        certPath = "/test/configs/certs/ca3cert.bin";
        certFile = string.concat(vm.projectRoot(), certPath);
        certificate = vm.readFileBinary(certFile);
        certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        espressoNitroTEEVerifier.verifyCACert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
        parentCertHash = certHash;

        certPath = "/test/configs/certs/client-cert.bin";
        certFile = string.concat(vm.projectRoot(), certPath);
        certificate = vm.readFileBinary(certFile);
        certHash = keccak256(certificate);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        espressoNitroTEEVerifier.verifyClientCert(certificate, parentCertHash);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
        vm.stopPrank();
    }
}
