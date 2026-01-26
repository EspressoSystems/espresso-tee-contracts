// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {RedBlackTreeLib} from "solady/utils/RedBlackTreeLib.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEspressoRollupSequencerManager} from "./interface/IEspressoRollupSequencerManager.sol";

contract EspressoRollupSequencerManager is Ownable2Step, IEspressoRollupSequencerManager {
    // Initialize the sequencer list as a binary red-black tree
    using RedBlackTreeLib for RedBlackTreeLib.Tree;

    RedBlackTreeLib.Tree sequencersList;

    // Create a hashMap to manage the nonce and the sequencer address
    mapping(uint256 => address) public nonceToSequencer;
    mapping(address => uint256) public sequencerToNonce;

    // Maintain a global counter to keep track of the nonce
    uint256 public globalNonce = 1;
    // Also maintain a counter to store the current number of sequencers
    uint256 public currentSequencerCount;

    modifier onlyOwnerOrSequencer(address sequencer) {
        if (msg.sender != owner() && msg.sender != sequencer) {
            revert Unauthorized();
        }
        _;
    }

    constructor(address[] memory initialSequencers) Ownable(msg.sender) {
        for (uint256 i = 0; i < initialSequencers.length; i++) {
            insertSequencer(initialSequencers[i]);
        }
    }

    /**
     * @notice Insert a new sequencer into the list
     *     @param sequencer The address of the sequencer
     */
    function insertSequencer(address sequencer) public onlyOwnerOrSequencer(sequencer) {
        if (sequencer == address(0)) {
            revert InvalidSequencer();
        }
        // Check if the sequencer already exist
        if (sequencerToNonce[sequencer] > 0) {
            revert SequencerAlreadyExists();
        }

        // Insert the sequencer into the list,
        sequencersList.insert(globalNonce);
        // Store the mappings
        nonceToSequencer[globalNonce] = sequencer;
        sequencerToNonce[sequencer] = globalNonce;
        emit SequencerAdded(sequencer, globalNonce);
        currentSequencerCount++;
        globalNonce++;
    }

    /**
     * @notice Remove a sequencer from the list
     *     @param sequencer The address of the sequencer
     */
    function removeSequencer(address sequencer) external onlyOwnerOrSequencer(sequencer) {
        uint256 nonce = sequencerToNonce[sequencer];
        // Check if the sequencer exists
        if (nonce == 0) {
            revert SequencerDoesNotExist();
        }

        // Remove the sequencer from the list
        sequencersList.remove(nonce);
        // Delete the mappings
        delete nonceToSequencer[nonce];
        delete sequencerToNonce[sequencer];
        currentSequencerCount--;
        emit SequencerRemoved(sequencer, nonce);
    }

    /**
     * @notice Get the current sequencer for a given view number
     *     This function is supposed to be called off-chain because
     *     it is computationally expensive
     *     @param viewNumber The view number
     */
    function getCurrentSequencer(uint256 viewNumber) external view returns (address) {
        if (currentSequencerCount == 0) {
            revert SequencerListIsEmpty();
        }

        // Take the mod of the viewNumber and the currentSequencerCount
        uint256 index = viewNumber % currentSequencerCount;
        // First get the first sequencer
        bytes32 sequencerLocation = sequencersList.first();
        uint256 sequencerValue;

        // get the first sequencer value
        if (index == 0) {
            sequencerValue = RedBlackTreeLib.value(sequencerLocation);
            return nonceToSequencer[sequencerValue];
        }

        for (uint256 i = 1; i <= index; i++) {
            sequencerLocation = RedBlackTreeLib.next(sequencerLocation);
        }

        sequencerValue = RedBlackTreeLib.value(sequencerLocation);
        return nonceToSequencer[sequencerValue];
    }
}
