// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Safe} from "safe-utils/Safe.sol";

import {IEspressoTEEVerifier} from "../src/interface/IEspressoTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";

contract MultiSigTransfer is Script {
    using Safe for *;

    Safe.Client safe;

    bytes32 constant NitroStack = keccak256(bytes("Nitro"));
    bytes32 constant OptimismStack = keccak256(bytes("Optimism"));

    error UnknownStack();
    error InvalidTargetChainForStack(uint256 chainID);
    
    // This is a mapping of chainID to address that represents the cannonical Espresso multi sig wallet addresses
    // for the Nitro integration.
    mapping (uint256 => address) NitroMultiSigWallets;
    // Similarly this is to record cannonical Espresso Multi-Sig wallets for the Optimism integration
    mapping (uint256 => address) OptimismMultiSigWallets;
    
    address[] internal batchTargets;
    bytes[] internal batchData;

    address newOwner;
    address teeVerifierAddress;
    address proposerAddress;
    uint256 originalOwnerPrivateKey;
    string derivationPath;

    IEspressoTEEVerifier teeVerifier;
    Ownable ownableTeeVerifier;
    address originalTeeVerifierOwner;
    Ownable2Step ownable2StepTeeVerifier;

    IEspressoNitroTEEVerifier nitroVerifier;
    Ownable ownableNitroTeeVerifier;
    address originalNitroTeeVerifierOwner;
    Ownable2Step ownable2StepNitroTeeVerifier;

    IEspressoSGXTEEVerifier sgxVerifier;
    Ownable ownableSGXTeeVerifier;
    address originalSGXTeeVerifierOwner;
    Ownable2Step ownable2StepSGXTeeVerifier;

    // Event signaling that the script has successfully initiated ownership transfers for the given set of TEEVerifier contracts.
    event AllOwnershipTransfersStarted(
        address teeVerifier, address nitroVerifier, address sgxVerifier
    );

    function setUpNitroMultiSigAddresses() internal{
        NitroMultiSigWallets[1] = address(0x6Dc61D9E366697979f69D89a154f2F8cd2F11dA5); // Eth Mainnet
        NitroMultiSigWallets[11155111] = address(0x6Dc61D9E366697979f69D89a154f2F8cd2F11dA5); // Eth Sepolia
        NitroMultiSigWallets[42161] = address(0x6Dc61D9E366697979f69D89a154f2F8cd2F11dA5); // Arb One
        // This is the result of narrow support across Safe wallet UI providers. None of them currently (20/01/2026) support Arb sepolia, so we have a different address here
        // NitroMultiSigWallets[421614] = address(0x054E02d743A68dC62076E816fc1f44d57fB4e3ce); // Arb Sepolia. Uncomment this when the underlying library supports arb sepolia multi-sigs
    }

    function parseMultiSigAddressFromStack(string memory stack) internal{
        bytes32 stackHash = keccak256(bytes(stack));
        // try to parse owner address based on stack and chain ID
        if (stackHash == NitroStack) {
            newOwner = NitroMultiSigWallets[block.chainid];
        } else if (stackHash == OptimismStack){
            newOwner = OptimismMultiSigWallets[block.chainid];
        } else {
            // Revert if the stack is unknown to the script.
            revert UnknownStack();
        }
        // if the address hasn't been initialized (meaning we don't have a multi-sig wallet on this chain for this stack), do not execute the transaction.
        if (newOwner == address(0)){
            revert InvalidTargetChainForStack(block.chainid);
        }

    }

    // This function is executed by the forge VM whenever the script is executed using forge script.
    function setUp() public {
        setUpNitroMultiSigAddresses();
        // Get operation mode env var
        bool isSafeMode = vm.envBool("SAFE_MODE");
        // Get transfer initiation env vars
        teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        originalOwnerPrivateKey = vm.envUint("PRIVATE_KEY");
        // Get transfer acceptance env vars
        derivationPath = vm.envString("LEDGER_DERIVATION_PATH");
        proposerAddress = vm.envAddress("PROPOSER_ADDRESS");

        if (isSafeMode) {
            string memory stackString = vm.envString("INTEGRATION_STACK");
            //This function internally initializes newOwner.
            parseMultiSigAddressFromStack(stackString);
        } else {
            newOwner = vm.envAddress("MULTISIG_CONTRACT_ADDRESS");
        }
        // Initialize the safe API client
        safe.initialize(newOwner);

        setUpContractVars();
    }

    // testSetUp is a helper function to handle the parts of the setUp() function related to the unit tests.
    // setUp() won't be called for this contract when run in a unit test context, so it's useful to have this to enable testing.
    function testSetUp() internal {
        setUpNitroMultiSigAddresses();
        newOwner = vm.envAddress("MULTISIG_CONTRACT_ADDRESS");
        teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");

        setUpContractVars();
    }

    // setUpContractVars() populates contract variables at the contract state level in order to compartmentalize this logic for unit tests and normal execution.
    function setUpContractVars() internal {
        teeVerifier = IEspressoTEEVerifier(teeVerifierAddress);
        ownableTeeVerifier = Ownable(address(teeVerifier));
        originalTeeVerifierOwner = ownableTeeVerifier.owner();
        ownable2StepTeeVerifier = Ownable2Step(address(teeVerifier));

        nitroVerifier = teeVerifier.espressoNitroTEEVerifier();
        ownableNitroTeeVerifier = Ownable(address(nitroVerifier));
        originalNitroTeeVerifierOwner = ownableNitroTeeVerifier.owner();
        ownable2StepNitroTeeVerifier = Ownable2Step(address(nitroVerifier));

        sgxVerifier = teeVerifier.espressoSGXTEEVerifier();
        ownableSGXTeeVerifier = Ownable(address(sgxVerifier));
        originalSGXTeeVerifierOwner = ownableSGXTeeVerifier.owner();
        ownable2StepSGXTeeVerifier = Ownable2Step(address(sgxVerifier));
    }

    // initiateTransfer() is a helper function for this script that allows the
    // original owner of the TEEVerifier contracts to initiate ownership transfer to the multi-sig wallet.
    // Reverts:
    //        - If there is not an appropriate OwnershipTransferStarted event emitted by any of the TEEVerifier contracts
    function initiateTransfer() internal {
        // After each step, we assert that the owner of the contract is still the original owner, but that the pending owner has updated.
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

    // proposeOwnershipAcceptaceTransaction is a function that utilizes the safe-utils library and Safe.Client to
    // interact with the safe-transaction-service API to propose a batch transaction for accepting ownership of the TEEVerifier contracts.
    // Return values:
    //              - bytes32 txHash: The transaction hash of the multi-sig transaction that was proposed to the web UI.
    function proposeOwnershipAcceptanceTransaction() internal returns (bytes32) {
        // Generate transaction target and data arrays for signing.
        bytes memory transactionDataSGX =
            abi.encodeCall(ownable2StepSGXTeeVerifier.acceptOwnership, ());
        bytes memory transactionDataNitro =
            abi.encodeCall(ownable2StepNitroTeeVerifier.acceptOwnership, ());
        bytes memory transactionData = abi.encodeCall(ownable2StepTeeVerifier.acceptOwnership, ());

        addToBatch(address(sgxVerifier), transactionDataSGX);
        addToBatch(address(nitroVerifier), transactionDataNitro);
        addToBatch(address(teeVerifier), transactionData);

        return safe.proposeTransactions(batchTargets, batchData, proposerAddress, derivationPath);
    }

    // addToBatch is a helper function for appending a transaction to the current batch being built for this ownership transfer.
    // Return values:
    //              - txHash: a bytes32 value representing the transaction hash proposed to the multi-sig wallet.
    function addToBatch(address target, bytes memory callData) internal {
        batchTargets.push(target);
        batchData.push(callData);
    }

    // assertTransferInitiated is a helper function to handle asserting when an ownership transfer has been initiated on an Ownable2Step implementing contract
    // Params:
    //       - contractAddress: The address to a smart contract that implements Ownable, and Ownable2Step.
    //       - originalOwner: the original owner of the contract (In this script it's assumed to be an EOA).
    //       - targetOwner: The address to which ownership transfer has (supposedly) been initiated.
    //
    // Reverts: if the contract at contractAddress doesn't hold the desired ownership transfer pending state.
    function assertTransferInitiated(
        address contractAddress,
        address originalOwner,
        address targetOwner
    ) internal {
        require(
            Ownable(contractAddress).owner() == originalOwner,
            "Current owner of contract is not the original owner"
        );
        require(
            Ownable2Step(contractAddress).pendingOwner() == targetOwner,
            "Current owner of contract is not the target owner"
        );
    }

    // testTransferEntrypoint() is a helper function that serves as a testing entry point for this script.
    // Its purpose is to trick the vm into thinking that the test is not making cross-contract calls and overwriting msg.sender.
    // This allows us to spoof more accurate testing conditions, as this script won't ever be deployed/called on chain.
    function transferTestEntrypoint() public {
        testSetUp();

        vm.startPrank(msg.sender);

        initiateTransfer();

        vm.stopPrank();
    }

    // The main entrypoint for the script when run using `forge script`
    // This entrypoint will broadcast the transaction on chain.
    function run() external {
        // Start broadcast with original signers key
        vm.startBroadcast(originalOwnerPrivateKey);

        initiateTransfer();

        vm.stopBroadcast();

        // Start broadcast with proposers address
        vm.startBroadcast(proposerAddress);
        bytes32 txHash = proposeOwnershipAcceptanceTransaction();
        console2.log("multi-sig transaction hash:");
        console2.logBytes32(txHash);

        vm.stopBroadcast();
    }
}
