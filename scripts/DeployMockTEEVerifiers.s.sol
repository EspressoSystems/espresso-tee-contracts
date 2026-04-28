// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifierMock} from "@espresso-tee/mocks/EspressoTEEVerifier.sol";
import {EspressoNitroTEEVerifierMock} from "@espresso-tee/mocks/EspressoNitroTEEVerifierMock.sol";
import {IEspressoNitroTEEVerifier} from "@espresso-tee/interface/IEspressoNitroTEEVerifier.sol";

/**
 * @title DeployMockTEEVerifiers
 * @notice Deploys all mock TEE verifier contracts in one script.
 *         These mock contracts skip attestation verification but still require
 *         signers to be registered before they can be used.
 *
 * Usage:
 *   forge script scripts/DeployMockTEEVerifiers.s.sol:DeployMockTEEVerifiers \
 *       --rpc-url "$RPC_URL" \
 *       --private-key "$PRIVATE_KEY" \
 *       --broadcast
 */
contract DeployMockTEEVerifiers is Script {
    function run() external {
        vm.startBroadcast();

        // 1. Deploy Nitro Mock Verifier
        EspressoNitroTEEVerifierMock nitroMock = new EspressoNitroTEEVerifierMock();
        console2.log("EspressoNitroTEEVerifierMock deployed at:", address(nitroMock));

        // 2. Deploy main TEE Verifier Mock with reference to Nitro mock
        EspressoTEEVerifierMock teeVerifierMock =
            new EspressoTEEVerifierMock(IEspressoNitroTEEVerifier(address(nitroMock)));
        console2.log("EspressoTEEVerifierMock deployed at:", address(teeVerifierMock));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write Nitro Mock address
        vm.writeJson(
            vm.serializeAddress("", "EspressoNitroTEEVerifierMock", address(nitroMock)),
            string.concat(dir, "/", chainId, "-nitro-verifier-mock.json")
        );

        // Write TEE Verifier Mock address
        vm.writeJson(
            vm.serializeAddress("", "EspressoTEEVerifierMock", address(teeVerifierMock)),
            string.concat(dir, "/", chainId, "-espresso-tee-verifier-mock.json")
        );

        vm.stopBroadcast();
    }
}
