// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IEspressoRollupSequencerManager {
    event SequencerAdded(address indexed sequencer);
    event SequencerRemoved(address indexed sequencer);

    error InvalidSequencer();
    error SequencerAlreadyExists();
    error SequencerDoesNotExist();
    error Unauthorized();

    function insertSequencer(address sequencer) external;

    function removeSequencer(address sequencer) external;

    function getCurrentSequencer(uint256 nonce) external view returns (address);
}
