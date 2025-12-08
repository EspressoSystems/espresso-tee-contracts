pragma solidity 0.8.25;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Script} from "forge-std/Script.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";


contract MultiSigTransfer is Script{

    // Event signaling that the script has successfully initiated ownership transfers for the given set of TEEVerifier contracts.
    event AllOwnershipTransfersStarted(address teeVerifier, address nitroVerifier, address sgxVerifier);

    // startTransfer(address, address) is a helper function for this script that allows the
    // original owner of the TEEVerifier contracts to initial ownership transfer to the multi-sig wallet.
    // Reverts:
    //        - If there is not an appropriate OwnershipTransferStarted event emitted by any of the TEEVerifier contracts
    function startTransfer(address newOwner, address teeVerifier_) internal {
        // grab relevant constructs for all contracts.
        IEspressoTEEVerifier teeVerifier = IEspressoTEEVerifier(teeVerifier_);
        Ownable ownableTeeVerifier = Ownable(address(teeVerifier));
        Ownable2Step ownable2StepTeeVerifier = Ownable2Step(address(teeVerifier));

        IEspressoNitroTEEVerifier nitroVerifier = teeVerifier.espressoNitroTEEVerifier();
        Ownable ownableNitroTeeVerifier = Ownable(address(nitroVerifier));
        Ownable2Step ownable2StepNitroTeeVerifier = Ownable2Step(address(nitroVerifier));

        IEspressoSGXTEEVerifier sgxVerifier = teeVerifier.espressoSGXTEEVerifier();
        Ownable ownableSGXTeeVerifier = Ownable(address(sgxVerifier));
        Ownable2Step ownable2StepSGXTeeVerifier = Ownable2Step(address(sgxVerifier));

        vm.expectCall(address(sgxVerifier), abi.encodeCall(ownable2StepSGXTeeVerifier.transferOwnership, newOwner));
        ownable2StepSGXTeeVerifier.transferOwnership(newOwner);
        vm.expectCall(address(nitroVerifier), abi.encodeCall(ownable2StepNitroTeeVerifier.transferOwnership, newOwner));
        ownable2StepNitroTeeVerifier.transferOwnership(newOwner);
        vm.expectCall(address(teeVerifier), abi.encodeCall(ownable2StepTeeVerifier.transferOwnership, newOwner));
        ownable2StepTeeVerifier.transferOwnership(newOwner);

        emit AllOwnershipTransfersStarted(address(teeVerifier), address(nitroVerifier), address(sgxVerifier));
    }
    
    // doTransfer is a helper function that captures the main logic of this script.
    // It's purpose is to allow for the creation of separate forge script and forge tests entry points.
    // This also allows the normal semantics for running this script to broadcast the transactions on chain.
    function doTransfer() internal {
        address newOwner = vm.envAddress("MULTISIG_CONTRACT_ADDRESS");

        address teeVerifier = vm.envAddress("TEE_VERIFIER_ADDRESS");

        startTransfer(newOwner, teeVerifier);
    }
     
    // testTransfer() is a helper function that serves as a testing entry point for this script
    // its purpose is to trick the vm into thinking that the test is not making overwriting msg.sender making the call
    // seem like its coming from the contract. This is a different behavior between using scripts in tests vs forge script.
    function transferTestEntrypoint() public{
        vm.startPrank(msg.sender);

        doTransfer();

        vm.stopPrank();
    }
    
    // The main entrypoint for the script when run using `forge script`
    // This entrypoint will broadcast the transaction on chain.
    function run() external {
        vm.startBroadcast();

        doTransfer();

        vm.stopBroadcast();
    }
}    
