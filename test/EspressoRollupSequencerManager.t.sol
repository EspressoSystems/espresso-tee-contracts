// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {EspressoRollupSequencerManager} from "../src/EspressoRollupSequencerManager.sol";
import {IEspressoRollupSequencerManager} from "../src/interface/IEspressoRollupSequencerManager.sol";

contract EspressoRollupSequencerManagerTest is Test {
    EspressoRollupSequencerManager public rollupSequencerManager;
    address[] public initialSequencers;

    function setUp() public {
        rollupSequencerManager = new EspressoRollupSequencerManager(initialSequencers);
    }

    function testInsertSequencer() public {
        address sequencer = address(0x123);
        vm.expectEmit(true, true, true, true);
        emit IEspressoRollupSequencerManager.SequencerAdded(sequencer, 1);
        rollupSequencerManager.insertSequencer(sequencer);
        assertEq(rollupSequencerManager.currentSequencerCount(), 1);
        assertEq(rollupSequencerManager.sequencerToNonce(sequencer), 1);
        assertEq(rollupSequencerManager.nonceToSequencer(1), sequencer);
        assertEq(rollupSequencerManager.globalNonce(), 2);
    }

    function testInsertSequencerFailsIfSequencerAlreadyExists() public {
        address sequencer = address(0x123);
        rollupSequencerManager.insertSequencer(sequencer);
        vm.expectRevert(IEspressoRollupSequencerManager.SequencerAlreadyExists.selector);
        rollupSequencerManager.insertSequencer(sequencer);
    }

    function testInsertFailsIfNotAuthorized() public {
        address sequencer = address(0x123);
        vm.prank(address(0x126));
        vm.expectRevert(IEspressoRollupSequencerManager.Unauthorized.selector);
        rollupSequencerManager.insertSequencer(sequencer);
    }

    function testRemoveSequencer() public {
        address sequencer = address(0x123);
        rollupSequencerManager.insertSequencer(sequencer);
        vm.expectEmit(true, true, true, true);
        emit IEspressoRollupSequencerManager.SequencerRemoved(sequencer, 1);
        rollupSequencerManager.removeSequencer(sequencer);
        assertEq(rollupSequencerManager.currentSequencerCount(), 0);
        assertEq(rollupSequencerManager.sequencerToNonce(sequencer), 0);
        assertEq(rollupSequencerManager.nonceToSequencer(1), address(0));
        // Check global nonce should not change
        assertEq(rollupSequencerManager.globalNonce(), 2);
    }

    function testRemoveSequencerFailsIfSequencerDoesNotExist() public {
        address sequencer = address(0x123);
        vm.expectRevert(IEspressoRollupSequencerManager.SequencerDoesNotExist.selector);
        rollupSequencerManager.removeSequencer(sequencer);
    }

    function testRemoveSequencerFailsIfNotAuthorized() public {
        address sequencer = address(0x123);
        rollupSequencerManager.insertSequencer(sequencer);
        vm.prank(address(0x126));
        vm.expectRevert(IEspressoRollupSequencerManager.Unauthorized.selector);
        rollupSequencerManager.removeSequencer(sequencer);
    }

    function testGetCurrentSequencer() public {
        address sequencer1 = address(0x123);
        address sequencer2 = address(0x456);
        rollupSequencerManager.insertSequencer(sequencer1);
        rollupSequencerManager.insertSequencer(sequencer2);
        assertEq(rollupSequencerManager.getCurrentSequencer(1), sequencer2);
        assertEq(rollupSequencerManager.getCurrentSequencer(2), sequencer1);
    }

    function testGetCurrentSequencerFailsIViewNumberGreaterThanSequencerLength() public {
        address sequencer1 = address(0x123);
        address sequencer2 = address(0x456);
        rollupSequencerManager.insertSequencer(sequencer1);
        rollupSequencerManager.insertSequencer(sequencer2);
        assertEq(rollupSequencerManager.getCurrentSequencer(5), sequencer2);
        // remove sequencer
        rollupSequencerManager.removeSequencer(sequencer1);
        assertEq(rollupSequencerManager.getCurrentSequencer(5), sequencer2);
    }
}
