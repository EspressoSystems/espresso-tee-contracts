// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {
    TransparentUpgradeableProxy
} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {
    OwnableUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {ITEEHelper} from "../src/interface/ITEEHelper.sol";
import {ServiceType} from "../src/types/Types.sol";

contract EspressoSGXTEEVerifierTest is Test {
    // Owner of the ProxyAdmin contracts that get auto-created by TransparentUpgradeableProxy
    address proxyAdminOwner = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

    EspressoTEEVerifier espressoTEEVerifier;
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    bytes32 reportDataHash =
        bytes32(0x38f8abca50cdede6a00d405856857bc3d81135624ee0e287640956d11cc22d5e);
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);

    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);

    function setUp() public {
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );
        espressoTEEVerifier = _deployTEEVerifierWithPlaceholders();
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        espressoSGXTEEVerifier = _deploySGX(address(espressoTEEVerifier));
        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(espressoSGXTEEVerifier))
        );
        espressoTEEVerifier.setEnclaveHash(
            enclaveHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        espressoTEEVerifier.setEnclaveHash(
            enclaveHash, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
        vm.stopPrank();
    }

    function _deployTEEVerifierWithPlaceholders() internal returns (EspressoTEEVerifier) {
        EspressoTEEVerifier impl = new EspressoTEEVerifier();
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(impl),
            proxyAdminOwner,
            abi.encodeCall(
                EspressoTEEVerifier.initialize,
                (
                    adminTEE,
                    IEspressoSGXTEEVerifier(address(0xDEAD)),
                    IEspressoNitroTEEVerifier(address(0xBEEF))
                )
            )
        );
        return EspressoTEEVerifier(address(proxy));
    }

    function _deploySGX(address teeVerifier) internal returns (EspressoSGXTEEVerifier) {
        EspressoSGXTEEVerifier impl = new EspressoSGXTEEVerifier();
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(impl), proxyAdminOwner, "");
        EspressoSGXTEEVerifier proxied = EspressoSGXTEEVerifier(address(proxy));
        vm.prank(teeVerifier);
        proxied.initialize(teeVerifier, v3QuoteVerifier);
        return proxied;
    }

    function testRegisterBatchPoster() public {
        vm.startPrank(adminTEE);
        // bytes memory attestation = vm.readFileBinary("/test/configs/attestation.bin");
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        // take keccak256 hash of the address of proxyAdmin

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(batchPosterAddress);

        // Convert the data to bytes32 and pass it to the verify function
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
        assertTrue(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );
        vm.stopPrank();
    }

    function testRegisterCaffNode() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testRegisterBatchPosterInvalidQuote() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }

    function testRegisterCaffNodeInvalidQuote() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.CaffNode);
    }

    function testRegisterBatchPosterInvalidAddress() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072);

        bytes memory data = abi.encodePacked(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }

    function testRegisterCaffNodeInvalidAddress() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testRegisterBatchPosterInvalidDataLength() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        // encode adds padding and the length should become incorrect
        bytes memory data = abi.encode(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidDataLength.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }

    function testRegisterCaffNodeInvalidDataLength() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        // encode adds padding and the length should become incorrect
        bytes memory data = abi.encode(caffNodeAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidDataLength.selector);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testDeleteEnclaveHashes() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);

        // Verify signer is valid after registration
        assertTrue(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = enclaveHash;
        espressoTEEVerifier.deleteEnclaveHashes(
            enclaveHashes, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(enclaveHash, ServiceType.BatchPoster),
            false
        );
        // NOTE: Signers remain in registeredServices (not cleaned to avoid DoS)
        // isSignerValid returns false (automatic revocation via hash check)
        assertFalse(
            espressoSGXTEEVerifier.isSignerValid(batchPosterAddress, ServiceType.BatchPoster)
        );
        vm.stopPrank();
    }

    /**
     * Test verify quote verifies that if correct quote and report data hash is passed
     *     then the function does not revert
     */
    function testVerifyQuoteValid() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * Test verify quote reverts if incorrect header is passed
     */
    function testVerifyInvalidHeaderInQuote() public {
        string memory quotePath = "/test/configs/incorrect_header_in_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory invalidQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidHeaderVersion.selector);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(invalidQuote, data, ServiceType.BatchPoster);
    }

    /**
     * Test verify quote reverts if incorrect quote is passed
     */
    function testVerifyInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory invalidQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(invalidQuote, data, ServiceType.BatchPoster);
    }

    /**
     * Test incorrect report data hash
     */
    function testIncorrectReportDataHash() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        address batchPosterAddress = address(0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }

    function testVerifyQuoteEmptyRawQuote() public {
        bytes memory sampleQuote = hex"";
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert();
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }

    function testVerifyQuoteEmptyReportDataHash() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        address batchPosterAddress = address(0);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        vm.expectRevert();
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
    }
    /**
     * Test verify quote reverts if incorrect enclaveHash is passed
     */

    function testIncorrectMrEnclave() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        vm.prank(adminTEE);
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = enclaveHash;
        espressoTEEVerifier.deleteEnclaveHashes(
            hashes, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEHelper.InvalidEnclaveHash.selector, enclaveHash, ServiceType.BatchPoster
            )
        );
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        espressoTEEVerifier.registerService(
            sampleQuote,
            abi.encodePacked(batchPosterAddress),
            IEspressoTEEVerifier.TeeType.SGX,
            ServiceType.BatchPoster
        );
    }

    function testSetEnclaveHash() public {
        vm.startPrank(adminTEE);
        bytes32 newMrEnclave = bytes32(hex"01");
        espressoTEEVerifier.setEnclaveHash(
            newMrEnclave, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave, ServiceType.BatchPoster),
            true
        );
        espressoTEEVerifier.setEnclaveHash(
            newMrEnclave, false, IEspressoTEEVerifier.TeeType.SGX, ServiceType.BatchPoster
        );
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave, ServiceType.BatchPoster),
            false
        );
        vm.stopPrank();
        // Check that only tee verifier can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.BatchPoster);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        espressoTEEVerifier.setEnclaveHash(
            newMrEnclave, true, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave, ServiceType.CaffNode), true
        );
        espressoTEEVerifier.setEnclaveHash(
            newMrEnclave, false, IEspressoTEEVerifier.TeeType.SGX, ServiceType.CaffNode
        );
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHash(newMrEnclave, ServiceType.CaffNode), false
        );
        vm.stopPrank();
        // Check that only tee verifier can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(ITEEHelper.UnauthorizedTEEVerifier.selector, fakeAddress)
        );
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testSetQuoteVerifier() public {
        vm.startPrank(adminTEE);

        espressoTEEVerifier.setQuoteVerifier(address(espressoSGXTEEVerifier));
        assertEq(address(espressoSGXTEEVerifier.quoteVerifier()), address(espressoSGXTEEVerifier));
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert(
            abi.encodeWithSelector(
                OwnableUpgradeable.OwnableUnauthorizedAccount.selector, fakeAddress
            )
        );
        espressoTEEVerifier.setQuoteVerifier(address(espressoSGXTEEVerifier));
        vm.stopPrank();
    }

    function testInitializeCannotRunTwice() public {
        vm.prank(adminTEE);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        espressoSGXTEEVerifier.initialize(adminTEE, v3QuoteVerifier);
    }
}
