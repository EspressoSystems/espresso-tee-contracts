// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {CertManager} from "@nitro-validator/CertManager.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

contract EspressoTEEVerifierTest is Test {
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash = bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293);
    bytes nitroPubKey =
        hex"090e39a638094d9805b89a831b7e710db345e701bb0e9865a60b6b50089b3f4b89c168fbf2219ba79b6e86eb63decac3be0dd3e8fb4c0f1b39d4ecd4589704ff";

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);

        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(pcr0Hash, new CertManager());
        espressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);
        vm.stopPrank();
    }

    function testSGXRegisterSigner() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);
    }

    function testNitroRegisterSigner() public {
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);
        espressoTEEVerifier.registerSigner(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO
        );
    }

    function testSGXRegisterSignerWithInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);
    }

    function testSGXRegisteredSigners() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoTEEVerifier.registerSigner(sampleQuote, data, IEspressoTEEVerifier.TeeType.SGX);

        assertEq(
            espressoTEEVerifier.registeredSigners(
                batchPosterAddress, IEspressoTEEVerifier.TeeType.SGX
            ),
            true
        );
    }

    function testNitroRegisteredSigners() public {
        vm.warp(1_743_110_000);
        string memory attestationPath = "/test/configs/nitro-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-valid-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);
        bytes32 publicKeyHash = keccak256(nitroPubKey);
        address signerAddr = address(uint160(uint256(publicKeyHash)));
        espressoTEEVerifier.registerSigner(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(signerAddr, IEspressoTEEVerifier.TeeType.NITRO),
            true
        );
    }

    function testSGXRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0),
                IEspressoTEEVerifier.TeeType.SGX
            ),
            true
        );
    }

    function testNitroRegisteredEnclaveHash() public {
        assertEq(
            espressoTEEVerifier.registeredEnclaveHashes(
                bytes32(0xc980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293),
                IEspressoTEEVerifier.TeeType.NITRO
            ),
            true
        );
    }

    function testSetEspressoSGXTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoSGXTEEVerifier newEspressoSGXTEEVerifier =
            new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(newEspressoSGXTEEVerifier);
        assertEq(
            address(espressoTEEVerifier.espressoSGXTEEVerifier()),
            address(newEspressoSGXTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoSGXTEEVerifier(newEspressoSGXTEEVerifier);
        vm.stopPrank();
    }

    function testSetEspressoNitroTEEVerifier() public {
        vm.startPrank(adminTEE);
        IEspressoNitroTEEVerifier newEspressoNitroTEEVerifier =
            new EspressoNitroTEEVerifier(pcr0Hash, new CertManager());
        espressoTEEVerifier.setEspressoNitroTEEVerifier(newEspressoNitroTEEVerifier);
        assertEq(
            address(espressoTEEVerifier.espressoNitroTEEVerifier()),
            address(newEspressoNitroTEEVerifier)
        );
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoTEEVerifier.setEspressoNitroTEEVerifier(newEspressoNitroTEEVerifier);
        vm.stopPrank();
    }

    function testEspressoNitroTEEVerifySignature() public {
        vm.warp(1_743_620_000);
        // Using attestations where we have a created signature over data
        string memory attestationPath = "/test/configs/nitro-verify-attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), attestationPath);
        bytes memory attestation = vm.readFileBinary(inputFile);

        string memory signaturePath = "/test/configs/nitro-verify-signature.bin";
        string memory sigFile = string.concat(vm.projectRoot(), signaturePath);
        bytes memory signature = vm.readFileBinary(sigFile);

        bytes memory pubKey =
            hex"88195346c675ad5c352ee257ec027c092c995dabd8aa54d2c68f3fac378faf9f402e8eee3418bb434f6feeec541658cd99eec502ace6b145aa2e03ce231ec4e6";
        bytes32 publicKeyHash = keccak256(pubKey);
        address signerAddr = address(uint160(uint256(publicKeyHash)));
        espressoTEEVerifier.registerSigner(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO
        );

        assertEq(
            espressoTEEVerifier.registeredSigners(signerAddr, IEspressoTEEVerifier.TeeType.NITRO),
            true
        );

        // Hash and signature which was created sample go code in AWS Nitro Enclave
        bytes32 dataHash =
            bytes32(0xe6e6afefbcd45eac66b314ee8dd955f00cc55de22b504cbf6a0e3fe47715c822);
        bytes memory dataSignature =
            hex"00bdcf15ff1635e99be3dfa38f621ba104ec92e2be97f58c8af3eeacf0cf612c133a6964998903d490bc913ac4217849db5f1f490f6abe0f6814b7336f900ea501";

        // Adjusting ECDSA signature 'v' value for Ethereum compatibility
        // Get `v` from the signature and verify the byte is in expected format for openzeppelin `ECDSA.recover`
        // https://github.com/ethereum/go-ethereum/issues/19751#issuecomment-504900739
        uint8 v = uint8(dataSignature[64]);
        if (v == 0 || v == 1) {
            dataSignature[64] = bytes1(v + 27);
        }
        // Verify we can recover the signer and we are registered
        assertEq(
            espressoTEEVerifier.verify(dataSignature, dataHash, IEspressoTEEVerifier.TeeType.NITRO),
            true
        );

        // invalidate the hash, expect revert
        dataHash = bytes32(0x00e6afefbcd45eac66b314ee8dd955f00cc55de22b504cbf6a0e3fe47715c822);
        vm.expectRevert(IEspressoTEEVerifier.InvalidSignature.selector);
        espressoTEEVerifier.verify(dataSignature, dataHash, IEspressoTEEVerifier.TeeType.NITRO);
    }

    /**
     * Test nitro register signer fails upon invalid attestation pcr0
     */
    function testNitroRegisterSignerInvalidPCR0Hash() public {
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

        // Expect revert
        vm.expectRevert(IEspressoNitroTEEVerifier.InvalidAWSEnclaveHash.selector);
        espressoTEEVerifier.registerSigner(
            attestation, signature, IEspressoTEEVerifier.TeeType.NITRO
        );
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
    function testOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoTEEVerifier.owner()), adminTEE);
        espressoTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoTEEVerifier.acceptOwnership();
        assertEq(address(espressoTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    // Test we cannot validate certificate if parent cert isnt validated on chain
    function testVerifyCertParentCertNotVerified() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        bytes memory certificate =
            hex"303082027b30820201a0030201020210019644224066e5be0000000068010efc300a06082a8648ce3d04030330818e310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533139303706035504030c30692d30663933623863306539366530393431382e75732d656173742d322e6177732e6e6974726f2d656e636c61766573301e170d3235303431373134323335335a170d3235303431373137323335365a308193310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753313e303c06035504030c35692d30663933623863306539366530393431382d656e63303139363434323234303636653562652e75732d656173742d322e6177733076301006072a8648ce3d020106052b8104002203620004cec0c64c56b21ce2e02cee8324ee54ea5d10d1194b79d88ba2897e43133420607cbe0402f60e4ecf213a0ff974e7c06ef5af8dc423384d39d941dc19bd4ccd768bda077a757c4ffbbb7ce60700b7189535c5794d8037813c8e10b108c9b0c29ba31d301b300c0603551d130101ff04023000300b0603551d0f0404030206c0300a06082a8648ce3d0403030368003065023041bc47d91a826558b0e348b67b81f123e777362a3bb1b80c88b77918b9474799423c3b5542f2ab376e1ecf39fc7783d60231008fe05fa76fb5171bb9eae274a3fcd38390048249563859071fb37bb77afc6b315086e49d2d2882535a269db1421895cf";
        bytes32 certHash = keccak256(certificate);
        bytes32 parentCertHash =
            hex"75a73bbe6ada19667613f9044edd49169ad8a0f1a409939a304b3fe5e28c9611";
        assertEq(
            espressoTEEVerifier.certVerified(certHash, IEspressoTEEVerifier.TeeType.NITRO), false
        );

        vm.expectRevert("parent cert unverified");
        espressoTEEVerifier.verifyCert(
            certificate, parentCertHash, true, IEspressoTEEVerifier.TeeType.NITRO
        );
        assertEq(
            espressoTEEVerifier.certVerified(certHash, IEspressoTEEVerifier.TeeType.NITRO), false
        );
        vm.stopPrank();
    }

    // Test we will validate the cert if parent cert is validated
    function testVerifyCert() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        bytes memory certificate =
            hex"308202bf30820244a00302010202103901be5541522dcb0275f2df76581a48300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303431363032343830375a170d3235303530363033343830375a3064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d323034356137623335376136313433302e75732d656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200045f520206dacc0fe47c3fa8d81570713612d7b3db4bcea7571cbc51d72e09f27ea6c70d072720307aa545b60d7181e1e2206baa2c8cb5f63ef84954be5cafd13fc81c95563bdb2d01d346b8853fbd4030a00dc6948a1a50a8782ee2f827b36575a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e041604141e54f9f5ac0a9e7298d586245179f3fb6c440508300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d04030303690030660231008a0bcb93d0799223d0bf30f6eab2023a23070a75554db1390f840e3b2fe6150abe37aa729f6b34b3b34e392e1d711f56023100a912321b8cefe9fbf90da3ef6b9acb89249e8fea283b41192001f5cc2d198a9427e484486582b4cc7c95ff9eac426ed6";
        bytes32 certHash = keccak256(certificate);
        bytes32 parentCertHash =
            hex"311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185";
        assertEq(
            espressoTEEVerifier.certVerified(certHash, IEspressoTEEVerifier.TeeType.NITRO), false
        );

        espressoTEEVerifier.verifyCert(
            certificate, parentCertHash, true, IEspressoTEEVerifier.TeeType.NITRO
        );
        assertEq(
            espressoTEEVerifier.certVerified(certHash, IEspressoTEEVerifier.TeeType.NITRO), true
        );
        vm.stopPrank();
    }

    // Test unsupported type for verifying certificate
    function testVerifyCertUnsupportedTEEType() public {
        vm.startPrank(adminTEE);
        vm.warp(1_744_913_000);
        bytes memory certificate =
            hex"308202bf30820244a00302010202103901be5541522dcb0275f2df76581a48300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3235303431363032343830375a170d3235303530363033343830375a3064310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c034157533136303406035504030c2d323034356137623335376136313433302e75732d656173742d322e6177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200045f520206dacc0fe47c3fa8d81570713612d7b3db4bcea7571cbc51d72e09f27ea6c70d072720307aa545b60d7181e1e2206baa2c8cb5f63ef84954be5cafd13fc81c95563bdb2d01d346b8853fbd4030a00dc6948a1a50a8782ee2f827b36575a381d53081d230120603551d130101ff040830060101ff020102301f0603551d230418301680149025b50dd90547e796c396fa729dcf99a9df4b96301d0603551d0e041604141e54f9f5ac0a9e7298d586245179f3fb6c440508300e0603551d0f0101ff040403020186306c0603551d1f046530633061a05fa05d865b687474703a2f2f6177732d6e6974726f2d656e636c617665732d63726c2e73332e616d617a6f6e6177732e636f6d2f63726c2f61623439363063632d376436332d343262642d396539662d3539333338636236376638342e63726c300a06082a8648ce3d04030303690030660231008a0bcb93d0799223d0bf30f6eab2023a23070a75554db1390f840e3b2fe6150abe37aa729f6b34b3b34e392e1d711f56023100a912321b8cefe9fbf90da3ef6b9acb89249e8fea283b41192001f5cc2d198a9427e484486582b4cc7c95ff9eac426ed6";
        bytes32 certHash = keccak256(certificate);
        bytes32 parentCertHash =
            hex"311d96fcd5c5e0ccf72ef548e2ea7d4c0cd53ad7c4cc49e67471aed41d61f185";

        vm.expectRevert(IEspressoTEEVerifier.UnsupportedTeeType.selector);
        espressoTEEVerifier.verifyCert(
            certificate, parentCertHash, true, IEspressoTEEVerifier.TeeType.SGX
        );
        vm.stopPrank();
    }
}
