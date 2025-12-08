// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {
    INitroEnclaveVerifier
} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";

import {EspressoTEEVerifier} from "../src/EspressoTEEVerifier.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "../src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "../src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";

import {MultiSigTransfer} from "../scripts/MultiSigTransfer.s.sol";

contract MultiSigTransferTest is Test{
    bytes constant revertReason = bytes("Ownable2Step: caller is not the new owner");
    // declare addresses for the test
    address originalOwner = address(141); // address value: 0x000000000000000000000000000000000000008c
    address newOwner = address(145); // address value: 0x0000000000000000000000000000000000000091
    address badNewOwner = address(146); // address value: 0x0000000000000000000000000000000000000092

    // string representations of addresses for vm.setEnv.
    string originalOwnerString = "0x000000000000000000000000000000000000008c";
    string newOwnerString = "0x0000000000000000000000000000000000000091";
    string badNewOwnerString = "0x0000000000000000000000000000000000000092";

    // Get the bytes values of the addresses so we can set env vars for the tests.
    bytes originalOwnerBytes = abi.encodePacked(originalOwner);
    bytes newOwnerBytes = abi.encodePacked(newOwner);
    bytes badNewOwnerBytes = abi.encodePacked(badNewOwner);
    // Env var constants used by ownership transfer script.
    string constant newOwnerEnv = "MULTISIG_CONTRACT_ADDRESS";
    string constant teeVerifierEnv = "TEE_VERIFIER_ADDRESS";
    string teeVerifierAddress;
    
    // TEE contract global variables for the tests.
    EspressoTEEVerifier espressoTEEVerifier;
    EspressoSGXTEEVerifier espressoSGXTEEVerifier;
    EspressoNitroTEEVerifier espressoNitroTEEVerifier;
    bytes32 enclaveHash =
        bytes32(0x01f7290cb6bbaa427eca3daeb25eecccb87c4b61259b1ae2125182c4d77169c0);
    //  Address of the automata V3QuoteVerifier deployed on sepolia
    address v3QuoteVerifier = address(0x6E64769A13617f528a2135692484B681Ee1a7169);
    bytes32 pcr0Hash = bytes32(0x555797ae2413bb1e4c352434a901032b16d7ac9090322532a3fccb9947977e8b);
    
    MultiSigTransfer multiSigTransfer;
    
    function setUp() public {
        // fork an eth sepolia network to populate the quote verifier contract code.
        vm.createSelectFork(
            "https://rpc.ankr.com/eth_sepolia/10a56026b3c20655c1dab931446156dea4d63d87d1261934c82a1b8045885923"
        );

        vm.startPrank(originalOwner);
        espressoSGXTEEVerifier = new EspressoSGXTEEVerifier(enclaveHash, v3QuoteVerifier);
        espressoNitroTEEVerifier = new EspressoNitroTEEVerifier(
            pcr0Hash, INitroEnclaveVerifier(0x2D7fbBAD6792698Ba92e67b7e180f8010B9Ec788)
        );
        espressoTEEVerifier =
            new EspressoTEEVerifier(espressoSGXTEEVerifier, espressoNitroTEEVerifier);

        teeVerifierAddress = Strings.toHexString(address(espressoTEEVerifier));

        multiSigTransfer = new MultiSigTransfer();
        vm.stopPrank();
    }
    // testValidTransfer tests accepting transfers to a valid address by attempting to accept ownership with the new owner address
    // populated via `vm.setEnv`
    function testValidTransfer() public{
        // set environment variables for the transfer script.
        vm.setEnv(newOwnerEnv, newOwnerString);
        vm.setEnv(teeVerifierEnv, teeVerifierAddress);
        vm.startPrank(originalOwner);
        console2.log("original owner:", originalOwner);
        console2.log("original owner according to contract:", Ownable(address(espressoTEEVerifier)).owner());

        // Expect emitted event from script, and initiate transfers.
        // vm.expectEmit(MultiSigTransfer.AllOwnershipTransfersStarted(address(espressoTEEVerifier), address(espressoNitroTEEVerifier), address(espressoSGXTEEVerifier)));
        multiSigTransfer.transferTestEntrypoint();
        vm.stopPrank();

        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(newOwner);
        console2.log("new owner:", newOwner);
        console2.log("pending owner:", Ownable2Step(address(espressoTEEVerifier)).pendingOwner());
        espressoTEEVerifier.acceptOwnership();
        assertEq(Ownable(address(espressoTEEVerifier)).owner(), newOwner);

        espressoNitroTEEVerifier.acceptOwnership();
        assertEq(Ownable(address(espressoNitroTEEVerifier)).owner(), newOwner);

        espressoSGXTEEVerifier.acceptOwnership();
        assertEq(Ownable(address(espressoSGXTEEVerifier)).owner(), newOwner);

        vm.stopPrank();
    }

    // testInvalidTransfer tests accepting transfers to a non valid address by attempting to accept ownership with the bad new owner address
    // populated via `vm.setEnv`
    function testInvalidTransfer() public{
        // set environment variables for the transfer script.
        vm.setEnv(newOwnerEnv, newOwnerString);
        vm.setEnv(teeVerifierEnv, teeVerifierAddress);

        // Expect emitted event from script, and initiate transfers.
        // vm.expectEmit(MultiSigTransfer.AllOwnershipTransfersStarted(address(espressoTEEVerifier), address(espressoNitroTEEVerifier), address(espressoSGXTEEVerifier)));
        
        vm.startPrank(originalOwner);
        console2.log("original owner:", originalOwner);
        console2.log("original owner according to contract:", Ownable(address(espressoTEEVerifier)).owner());
        multiSigTransfer.transferTestEntrypoint();

        vm.stopPrank();        
        // Expect emitted event from script, and initiate transfers.
        vm.startPrank(badNewOwner);
        vm.expectRevert(revertReason);
        espressoTEEVerifier.acceptOwnership();

        vm.expectRevert(revertReason);
        espressoNitroTEEVerifier.acceptOwnership();

        vm.expectRevert(revertReason);
        espressoSGXTEEVerifier.acceptOwnership();

        vm.stopPrank();
    }
    
}
