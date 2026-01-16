// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifierMock} from "src/mocks/EspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifierMock} from "src/mocks/EspressoSGXTEEVerifierMock.sol";
import {EspressoNitroTEEVerifierMock} from "src/mocks/EspressoNitroTEEVerifierMock.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";

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

        // 1. Deploy SGX Mock Verifier
        EspressoSGXTEEVerifierMock sgxMock = new EspressoSGXTEEVerifierMock();
        console2.log("EspressoSGXTEEVerifierMock deployed at:", address(sgxMock));

        // 2. Deploy Nitro Mock Verifier
        EspressoNitroTEEVerifierMock nitroMock = new EspressoNitroTEEVerifierMock();
        console2.log("EspressoNitroTEEVerifierMock deployed at:", address(nitroMock));

        // 3. Deploy main TEE Verifier Mock with references to SGX and Nitro mocks
        EspressoTEEVerifierMock teeVerifierMock = new EspressoTEEVerifierMock(
            IEspressoSGXTEEVerifier(address(sgxMock)),
            IEspressoNitroTEEVerifier(address(nitroMock))
        );
        console2.log("EspressoTEEVerifierMock deployed at:", address(teeVerifierMock));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write SGX Mock address
        vm.writeJson(
            vm.serializeAddress("", "EspressoSGXTEEVerifierMock", address(sgxMock)),
            string.concat(dir, "/", chainId, "-sgx-verifier-mock.json")
        );

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
