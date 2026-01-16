// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
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
        // Register enclave hash used by sample attestation.bin
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
        espressoSGXTEEVerifier.registerBatchPoster(sampleQuote, data);
        vm.stopPrank();
    }

    function testRegisterCaffNode() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        espressoSGXTEEVerifier.registerCaffNode(sampleQuote, data);
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
        espressoSGXTEEVerifier.registerBatchPoster(sampleQuote, data);
    }

    function testRegisterCaffNodeInvalidQuote() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.registerCaffNode(sampleQuote, data);
    }

    function testRegisterBatchPosterInvalidAddress() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address batchPosterAddress = address(0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072);

        bytes memory data = abi.encodePacked(batchPosterAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.registerBatchPoster(sampleQuote, data);
    }

    function testRegisterCaffNodeInvalidAddress() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);

        address caffNodeAddress = address(0x4C91660a37d613E1Bd278F9Db882Cc5ED2549072);

        bytes memory data = abi.encodePacked(caffNodeAddress);

        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.registerCaffNode(sampleQuote, data);
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
        espressoSGXTEEVerifier.registerBatchPoster(sampleQuote, data);
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
        espressoSGXTEEVerifier.registerCaffNode(sampleQuote, data);
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

        espressoSGXTEEVerifier.registerBatchPoster(sampleQuote, data);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        address[] memory batchPosters = new address[](1);
        batchPosters[0] = batchPosterAddress;
        espressoSGXTEEVerifier.deleteRegisteredBatchPosters(batchPosters);
        assertEq(espressoSGXTEEVerifier.registeredBatchPosters(batchPosterAddress), false);
        vm.stopPrank();

        // Check that only owner can delete the signer
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");

        espressoSGXTEEVerifier.deleteRegisteredBatchPosters(batchPosters);
        vm.stopPrank();

        // Similarly for CaffNode
        vm.startPrank(adminTEE);
        address caffNodeAddress = address(0xe2148eE53c0755215Df69b2616E552154EdC584f);

        bytes memory dataCaff = abi.encodePacked(caffNodeAddress);
        espressoSGXTEEVerifier.registerCaffNode(sampleQuote, dataCaff);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        address[] memory caffNodes = new address[](1);
        caffNodes[0] = caffNodeAddress;
        espressoSGXTEEVerifier.deleteRegisteredCaffNodes(caffNodes);
        assertEq(espressoSGXTEEVerifier.registeredCaffNodes(caffNodeAddress), false);
        vm.stopPrank();

        // Check that only owner can delete the signer
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.deleteRegisteredCaffNodes(caffNodes);
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
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash, ServiceType.BatchPoster);
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
        espressoSGXTEEVerifier.verify(invalidQuote, reportDataHash, ServiceType.BatchPoster);
        vm.stopPrank();
    }

    /**
     * Test verify quote reverts if incorrect quote is passed
     */
    function testVerifyInvalidQuote() public {
        string memory quotePath = "/test/configs/invalid_quote.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory invalidQuote = vm.readFileBinary(inputFile);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidQuote.selector);
        espressoSGXTEEVerifier.verify(invalidQuote, reportDataHash, ServiceType.BatchPoster);
        vm.stopPrank();
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
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0), ServiceType.BatchPoster);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        vm.expectRevert(IEspressoSGXTEEVerifier.InvalidReportDataHash.selector);
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0), ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testVerifyQuoteEmptyRawQuote() public {
        bytes memory sampleQuote = hex"";
        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash, ServiceType.BatchPoster);
        vm.stopPrank();

        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash, ServiceType.CaffNode);
    }

    function testVerifyQuoteEmptyReportDataHash() public {
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0), ServiceType.BatchPoster);

        vm.expectRevert();
        espressoSGXTEEVerifier.verify(sampleQuote, bytes32(0), ServiceType.CaffNode);
        vm.stopPrank();
    }
    /**
     * Test verify quote reverts if incorrect enclaveHash is passed
     */

    function testIncorrectMrEnclave() public {
        vm.startPrank(adminTEE);
        string memory quotePath = "/test/configs/attestation.bin";
        string memory inputFile = string.concat(vm.projectRoot(), quotePath);
        bytes memory sampleQuote = vm.readFileBinary(inputFile);
        bytes32 incorrectMrEnclave =
            bytes32(0x51dfe95acffa8a4075b716257c836895af9202a5fd56c8c2208dacb79c659ff1);
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(v3QuoteVerifier);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEspressoSGXTEEVerifier.InvalidEnclaveHash.selector,
                enclaveHash,
                ServiceType.BatchPoster
            )
        );
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash, ServiceType.BatchPoster);

        vm.expectRevert(
            abi.encodeWithSelector(
                IEspressoSGXTEEVerifier.InvalidEnclaveHash.selector,
                enclaveHash,
                ServiceType.CaffNode
            )
        );
        espressoSGXTEEVerifier.verify(sampleQuote, reportDataHash, ServiceType.CaffNode);
        vm.stopPrank();
    }

    function testSetEnclaveHash() public {
        vm.startPrank(adminTEE);
        bytes32 newMrEnclave = bytes32(hex"01");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.BatchPoster);
        assertEq(espressoSGXTEEVerifier.registeredBatchPosterEnclaveHashes(newMrEnclave), true);
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, false, ServiceType.BatchPoster);
        assertEq(espressoSGXTEEVerifier.registeredBatchPosterEnclaveHashes(newMrEnclave), false);
        vm.stopPrank();
        // Check that only owner can set the hash
        vm.startPrank(fakeAddress);
        vm.expectRevert("Ownable: caller is not the owner");
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.BatchPoster);
        vm.stopPrank();

        vm.startPrank(adminTEE);
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, true, ServiceType.CaffNode);
        assertEq(espressoSGXTEEVerifier.registeredCaffNodeEnclaveHashes(newMrEnclave), true);
        espressoSGXTEEVerifier.setEnclaveHash(newMrEnclave, false, ServiceType.CaffNode);
        assertEq(espressoSGXTEEVerifier.registeredCaffNodeEnclaveHashes(newMrEnclave), false);
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
