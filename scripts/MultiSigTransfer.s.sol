// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Script} from "forge-std/Script.sol";
import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";

contract MultiSigTransfer is Script {
    // Event signaling that the script has successfully initiated ownership transfers for the given set of TEEVerifier contracts.
    event AllOwnershipTransfersStarted(
        address teeVerifier, address nitroVerifier, address sgxVerifier
    );

    // startTransfer(address, address) is a helper function for this script that allows the
    // original owner of the TEEVerifier contracts to initiate ownership transfer to the multi-sig wallet.
    // Reverts:
    //        - If there is not an appropriate OwnershipTransferStarted event emitted by any of the TEEVerifier contracts
    function startTransfer(address newOwner, address teeVerifier_) internal {
        // grab relevant constructs for all contracts.
        IEspressoTEEVerifier teeVerifier = IEspressoTEEVerifier(teeVerifier_);
        Ownable ownableTeeVerifier = Ownable(address(teeVerifier));
        address originalTeeVerifierOwner = ownableTeeVerifier.owner();
        Ownable2Step ownable2StepTeeVerifier = Ownable2Step(address(teeVerifier));

        IEspressoNitroTEEVerifier nitroVerifier = teeVerifier.espressoNitroTEEVerifier();
        Ownable ownableNitroTeeVerifier = Ownable(address(nitroVerifier));
        address originalNitroTeeVerifierOwner = ownableTeeVerifier.owner();
        Ownable2Step ownable2StepNitroTeeVerifier = Ownable2Step(address(nitroVerifier));

        IEspressoSGXTEEVerifier sgxVerifier = teeVerifier.espressoSGXTEEVerifier();
        Ownable ownableSGXTeeVerifier = Ownable(address(sgxVerifier));
        address originalSGXTeeVerifierOwner = ownableTeeVerifier.owner();
        Ownable2Step ownable2StepSGXTeeVerifier = Ownable2Step(address(sgxVerifier));

        
        //After each step, we assert that the owner of the contract is still the original owner, but that the pending owner has updated.
        // If this doesn't hold, the transaction reverts.
        ownable2StepSGXTeeVerifier.transferOwnership(newOwner);
        assertTransferInitiated(address(sgxVerifier), originalSGXTeeVerifierOwner, newOwner);

        ownable2StepNitroTeeVerifier.transferOwnership(newOwner);
        assertTransferInitiated(address(nitroVerifier), originalNitroTeeVerifierOwner, newOwner);

        ownable2StepTeeVerifier.transferOwnership(newOwner);
        assertTransferInitiated(address(teeVerifier), originalTeeVerifierOwner, newOwner);

        emit AllOwnershipTransfersStarted(
            address(teeVerifier), address(nitroVerifier), address(sgxVerifier)
        );
    }

    //
    // assertTransferInitiated is a helper function to handle asserting when an ownership transfer has been initiated on an Ownable2Step implementing contract
    // Params:
    //       - contractAddress: The address to a smart contract that implements Ownable, and Ownable2Step.
    //       - originalOwner: the original owner of the contract (In this script it's assumed to be an EOA).
    //       - newOwner: The address to which ownership transfer has (supposedly) been initiated.
    //
    // Reverts: if the contract at contractAddress doesn't hold the desired ownership transfer pending state.
    function assertTransferInitiated(
        address contractAddress,
        address originalOwner,
        address newOwner
    ) internal {
        require(
            Ownable(contractAddress).owner() == originalOwner,
            "Current owner of contract is not the original owner"
        );
        require(
            Ownable2Step(contractAddress).pendingOwner() == newOwner,
            "Current owner of contract is not the original owner"
        );
    }

    // function assertOwnershipTransferSucceeded() {}

    // doTransfer is a helper function that captures the main logic of this script.
    // Its purpose is to allow for the creation of separate forge script and forge tests entry points.
    // This also allows the normal semantics for running this script to broadcast the transactions on chain.
    function doTransfer() internal {
        address newOwner = vm.envAddress("MULTISIG_CONTRACT_ADDRESS");

        address teeVerifier = vm.envAddress("TEE_VERIFIER_ADDRESS");

        startTransfer(newOwner, teeVerifier);
    }

    // testTransfer() is a helper function that serves as a testing entry point for this script
    // its purpose is to trick the vm into thinking that the test is not making cross-contract calls and overwriting msg.sender.
    // This allows us to spoof more accurate testing conditions, as this script won't ever be deployed/called on chain.
    function transferTestEntrypoint() public {
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
