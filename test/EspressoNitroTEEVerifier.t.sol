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
     * Test register signer fails upon invalid attestation pcr0
     */
    function testRegisterSignerInvalidPCR0Hash() public {
        vm.startPrank(adminTEE);
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        // Disable pcr0 hash
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);

        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
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
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), true);
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, false);
        assertEq(espressoNitroTEEVerifier.registeredEnclaveHash(pcr0Hash), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.setEnclaveHash(pcr0Hash, true);
        vm.stopPrank();
    }

    /**
     * Test we can delete a registered signer with only the correct admin address
     */
    function testDeleteRegisterSignerOwnership() public {
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
        espressoNitroTEEVerifier.registerSigner(attestation, signature);
        bytes memory pubKey =
            hex"090e39a638094d9805b89a831b7e710db345e701bb0e9865a60b6b50089b3f4b89c168fbf2219ba79b6e86eb63decac3be0dd3e8fb4c0f1b39d4ecd4589704ff";
        address signer = address(uint160(uint256(keccak256(pubKey))));
        assertEq(espressoNitroTEEVerifier.registeredSigners(signer), true);

        // start with incorrect admin address
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        address[] memory signersToDelete = new address[](1);
        signersToDelete[0] = signer;

        // verify we cant delete
        vm.expectRevert("Ownable: caller is not the owner");
        espressoNitroTEEVerifier.deleteRegisteredSigners(signersToDelete);

        // start with correct admin address
        vm.stopPrank();
        vm.startPrank(adminTEE);

        // delete and verify signer address is gone
        espressoNitroTEEVerifier.deleteRegisteredSigners(signersToDelete);
        assertEq(espressoNitroTEEVerifier.registeredSigners(signer), false);
    }

    function testVerifyCertParentCertNotVerified() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        bytes memory certificate =
            hex"303082027b30820201a0030201020210019644224066e5be0000000068010efc300a06082a8648ce3d04030330818e310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30692d30663933623863306539366530393431382e75732d656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303431373134323335335a170d3235303431373137323335365a308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30663933623863306539366530393431382d656e63303139363434323234303636653562652e75732d656173742d322e6177733076301006072a8648ce3d020106052b8104002203620004cec0c64c56b21ce2e02cee8324ee54ea5d10d1194b79d88ba2897e43133420607cbe0402f60e4ecf213a0ff974e7c06ef5af8dc423384d39d941dc19bd4ccd768bda077a757c4ffbbb7ce60700b7189535c5794d8037813c8e10b108c9b0c29ba31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030368003065023041bc47d91a826558b0e348b67b81f123e777362a3bb1b80c88b77918b9474799423c3b5542f2ab376e1ecf39fc7783d60231008fe05fa76fb5171bb9eae274a3fcd38390048249563859071fb37bb77afc6b315086e49d2d2882535a269db1421895cf";
        bytes32 certHash = keccak256(certificate);
        bytes32 parentCertHash =
            hex"75a73bbe6ada19667613f9044edd49169ad8a0f1a409939a304b3fe5e28c9611";
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);

        vm.expectRevert("parent cert unverified");
        espressoNitroTEEVerifier.verifyCert(certificate, parentCertHash, true);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);
        vm.stopPrank();
    }

    function testVerifyCert() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        bytes memory certificate =
            hex"308202bf30820244a00302010202103901be5541522dcb0275f2df76581a48300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303431363032343830375a170d3235303530363033343830375a3064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d323034356137623335376136313433302e75732d656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200045f520206dacc0fe47c3fa8d81570713612d7b3db4bcea7571cbc51d72e09f27ea6c70d072720307aa545b60d7181e1e2206baa2c8cb5f63ef84954be5cafd13fc81c95563bdb2d01d346b8853fbd4030a00dc6948a1a50a8782ee2f827b36575a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e041604141e54f9f5ac0a9e7298d586245179f3fb6c440508300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d04030303690030660231008a0bcb93d0799223d0bf30f6eab2023a23070a75554db1390f840e3b2fe6150abe37aa729f6b34b3b34e392e1d711f56023100a912321b8cefe9fbf90da3ef6b9acb89249e8fea283b41192001f5cc2d198a9427e484486582b4cc7c95ff9eac426ed6";
        bytes32 certHash = keccak256(certificate);
        bytes32 parentCertHash =
            hex"311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185";
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), false);

        espressoNitroTEEVerifier.verifyCert(certificate, parentCertHash, true);
        assertEq(espressoNitroTEEVerifier.certVerified(certHash), true);
    }
}
