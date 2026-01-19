// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {ITEEVerifier} from "../src/interface/ITEEVerifier.sol";
import {ServiceType} from "../src/types/Types.sol";

contract EspressoSGXTEEVerifierTest is Test {
    address proxyAdmin = address(140);
    address adminTEE = address(141);
    address fakeAddress = address(145);

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
        // Get the instance of the DCAP Attestation QuoteVerifier on the Arbitrum Sepolia Rollup
        vm.startPrank(adminTEE);
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(v3QuoteVerifier);
        espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, true, ServiceType.BatchPoster);
        espressoSGXTEEVerifier.setEnclaveHash(enclaveHash, true, ServiceType.CaffNode);
        vm.stopPrank();
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
            espressoSGXTEEVerifier.registeredSigners(ServiceType.BatchPoster, batchPosterAddress)
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

    function testDeleteRegisteredSigner() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        // Convert to bytes (dynamically sized)
        bytes memory data = abi.encodePacked(batchPosterAddress);

        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        address[] memory batchPosters = new address[](1);
        batchPosters[0] = batchPosterAddress;
        espressoSGXTEEVerifier.deleteSigners(batchPosters, ServiceType.BatchPoster);
        assertEq(
            espressoSGXTEEVerifier.registeredSigners(ServiceType.BatchPoster, batchPosterAddress),
            false
        );
        vm.stopPrank();

        // Check that only owner can delete the signer
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");

        espressoSGXTEEVerifier.deleteSigners(batchPosters, ServiceType.BatchPoster);
        vm.stopPrank();

        // Similarly for CaffNode
        vm.startPrank(adminTEE);
        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory dataCaff = abi.encodePacked(caffNodeAddress);
        espressoSGXTEEVerifier.registerService(sampleQuote, dataCaff, ServiceType.CaffNode);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        address[] memory caffNodes = new address[](1);
        caffNodes[0] = caffNodeAddress;
        espressoSGXTEEVerifier.deleteSigners(caffNodes, ServiceType.CaffNode);
        assertEq(
            espressoSGXTEEVerifier.registeredSigners(ServiceType.CaffNode, caffNodeAddress), false
        );
        vm.stopPrank();

        // Check that only owner can delete the signer
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.deleteSigners(caffNodes, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testEnclaveHashSignersAndDeleteEnclaveHashes() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        bytes memory data = abi.encodePacked(batchPosterAddress);
        espressoSGXTEEVerifier.registerService(sampleQuote, data, ServiceType.BatchPoster);

        address[] memory signers =
            espressoSGXTEEVerifier.enclaveHashSigners(enclaveHash, ServiceType.BatchPoster);
        assertEq(signers.length, 1);
        assertEq(signers[0], batchPosterAddress);

        bytes32[] memory enclaveHashes = new bytes32[](1);
        enclaveHashes[0] = enclaveHash;
        espressoSGXTEEVerifier.deleteEnclaveHashes(enclaveHashes, ServiceType.BatchPoster);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHashes(ServiceType.BatchPoster, enclaveHash),
            false
        );
        assertEq(
            espressoSGXTEEVerifier.registeredSigners(ServiceType.BatchPoster, batchPosterAddress),
            false
        );
        address[] memory signersAfter =
            espressoSGXTEEVerifier.enclaveHashSigners(enclaveHash, ServiceType.BatchPoster);
        assertEq(signersAfter.length, 0);
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
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(v3QuoteVerifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITEEVerifier.InvalidEnclaveHash.selector, enclaveHash, ServiceType.BatchPoster
            )
        );
        address batchPosterAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);
        espressoSGXTEEVerifier.registerService(
            sampleQuote, abi.encodePacked(batchPosterAddress), ServiceType.BatchPoster
        );
    }

    function testSetEnclaveHash() public {
        vm.startPrank(adminTEE);
        bytes32 newMrEnclave = bytes32(hex"01");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.BatchPoster);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHashes(ServiceType.BatchPoster, newMrEnclave),
            true
        );
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, false, ServiceType.BatchPoster);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHashes(ServiceType.BatchPoster, newMrEnclave),
            false
        );
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.BatchPoster);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.CaffNode);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHashes(ServiceType.CaffNode, newMrEnclave), true
        );
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, false, ServiceType.CaffNode);
        assertEq(
            espressoSGXTEEVerifier.registeredEnclaveHashes(ServiceType.CaffNode, newMrEnclave),
            false
        );
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.CaffNode);
        vm.stopPrank();
    }

    // Test Ownership transfer using Ownable2Step contract
    function testOwnershipTransfer() public {
        vm.startPrank(adminTEE);
        assertEq(address(espressoSGXTEEVerifier.owner()), adminTEE);
        espressoSGXTEEVerifier.transferOwnership(fakeAddress);
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        espressoSGXTEEVerifier.acceptOwnership();
        assertEq(address(espressoSGXTEEVerifier.owner()), fakeAddress);
        vm.stopPrank();
    }

    function testSetQuoteVerifier() public {
        vm.startPrank(adminTEE);

        espressoSGXTEEVerifier.setQuoteVerifier(address(espressoSGXTEEVerifier));
        assertEq(address(espressoSGXTEEVerifier.quoteVerifier()), address(espressoSGXTEEVerifier));
        vm.stopPrank();
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.setQuoteVerifier(address(espressoSGXTEEVerifier));
        vm.stopPrank();
    }
}
