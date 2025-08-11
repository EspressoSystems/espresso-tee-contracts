// // SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {RedBlackTreeLib} from "solady/utils/RedBlackTreeLib.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract EspressoRollupSequencerManager is Ownable2Step {
    // Initialize the sequencer list as a binary red-black tree
    RedBlackTreeLib.Tree sequencersList;
    // Thrown when the address is a contract
    error InvalidSequencer();
    error SequencerAlreadyExists();
    error SequencerDoesNotExist();
    error Unauthorized();

    // Create a hashMap to manage the nonce and the sequencer address
    mapping(uint256 => address) public nonceToSequencer;
    mapping(address => uint256) public sequencerToNonce;

    // Maintain a global counter to keep track of the nonce
    uint256 public globalNonce;
    // Also maintain a counter to store the current number of sequencers
    uint256 public currentSequencerCount;

    constructor(address[] memory initialSequencers) Ownable() {
        _transferOwnership(msg.sender);
        for (uint256 i = 0; i < initialSequencers.length; i++) {
            insertSequencer(initialSequencers[i]);
        }
    }

    /**
        @notice Insert a new sequencer into the list
        @param sequencer The address of the sequencer
     */
    function insertSequencer(address sequencer) public {
        // Check address is not a contract,
        // currently we only support EOAs
        if (sequencer.code.length > 0) {
            revert InvalidSequencer();
        }

        // Check if the sequencer already exist
        if (sequencerToNonce[sequencer] != 0) {
            revert SequencerAlreadyExists();
        }

        // Insert the sequencer into the list,
        // If the address already exist, it will throw an error
        sequencersList.insert(globalNonce);
        // Store the mappings
        nonceToSequencer[globalNonce] = sequencer;
        sequencerToNonce[sequencer] = globalNonce;
        globalNonce++;
        currentSequencerCount++;
    }

    /**
        @notice Remove a sequencer from the list
        @param sequencer The address of the sequencer
     */
    function removeSequencer(address sequencer) external {
        // Check that msg.sender should be the owner or the address of sequencer
        if (msg.sender != owner() && msg.sender != sequencer) {
            revert Unauthorized();
        }

        // Check if the sequencer exists
        if (sequencerToNonce[sequencer] == 0) {
            revert SequencerDoesNotExist();
        }

        // Remove the sequencer from the list
        uint256 nonce = sequencerToNonce[sequencer];
        sequencersList.remove(nonce);
        // Delete the mappings
        delete nonceToSequencer[nonce];
        delete sequencerToNonce[sequencer];
        currentSequencerCount--;
    }

    /**
        @notice Get the current sequencer for a given view number
        @param viewNumber The view number
     */
    function getCurrentSequencer(
        uint256 viewNumber
    ) external view returns (address) {
        // Take the mod of the viewNumber and the currentSequencerCount
        uint256 index = viewNumber % currentSequencerCount;
        // First get the first sequencer
        bytes32 sequencerLocation = sequencersList.first();
        uint256 sequencerValue;

        if (index == 0) {
            // get the first sequencer value
            sequencerValue = sequencersList.value(sequencerLocation);
            return nonceToSequencer[sequencerValue];
        }

        for (uint256 i = 1; i <= index; i++) {
            sequencerLocation = sequencersList.next(sequencerLocation);
        }

        sequencerValue = sequencersList.value(sequencerLocation);
        return nonceToSequencer[sequencerValue];
    }
}
