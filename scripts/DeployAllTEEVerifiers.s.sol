// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "@espresso-tee/EspressoTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "@espresso-tee/EspressoNitroTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "@espresso-tee/interface/IEspressoNitroTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployAllTEEVerifiers
 * @notice Deploys all TEE verifier contracts in a single transaction batch.
 *         EspressoNitroTEEVerifier is a non-proxy contract.
 *         EspressoTEEVerifier is deployed behind a TransparentUpgradeableProxy.
 *
 *      Deployment order:
 *      1. Deploy EspressoTEEVerifier proxy (with zero placeholder address for Nitro)
 *      2. Deploy EspressoNitroTEEVerifier with the actual TEEVerifier proxy address
 *      3. Update EspressoTEEVerifier with the actual Nitro address
 *
 * @dev deploy() optionally sets guardians via the guardians array parameter.
 *      run() reads guardian addresses from the GUARDIANS env var (comma-separated).
 */
contract DeployAllTEEVerifiers is Script {
    /**
     * @param proxyAdminOwner      Address that will own the auto-deployed ProxyAdmin.
     * @param nitroEnclaveVerifier Address of the AWS Nitro enclave verifier.
     * @param guardians            Optional guardian addresses to register on the TEEVerifier.
     * @return teeProxy      Address of the deployed EspressoTEEVerifier proxy.
     * @return teeImpl       Address of the deployed EspressoTEEVerifier implementation.
     * @return nitroVerifier Address of the deployed EspressoNitroTEEVerifier.
     */
    function deploy(
        address proxyAdminOwner,
        address nitroEnclaveVerifier,
        address[] memory guardians
    ) public returns (address teeProxy, address teeImpl, address nitroVerifier) {
        require(proxyAdminOwner != address(0), "proxyAdminOwner cannot be zero");
        // Step 1: Deploy TEEVerifier with zero placeholder address for Nitro
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log("TEEVerifier implementation deployed at:", address(teeVerifierImpl));

        TransparentUpgradeableProxy teeVerifierProxy = new TransparentUpgradeableProxy(
            address(teeVerifierImpl),
            proxyAdminOwner,
            abi.encodeWithSelector(
                EspressoTEEVerifier.initialize.selector,
                proxyAdminOwner,
                IEspressoNitroTEEVerifier(address(0))
            )
        );
        console2.log("TEEVerifier proxy deployed at:", address(teeVerifierProxy));

        teeProxy = address(teeVerifierProxy);
        teeImpl = address(teeVerifierImpl);

        // Step 2: Deploy NitroVerifier pointing to TEEVerifier
        EspressoNitroTEEVerifier nitro =
            new EspressoNitroTEEVerifier(teeProxy, nitroEnclaveVerifier);
        console2.log("NitroVerifier deployed at:", address(nitro));
        nitroVerifier = address(nitro);

        // Step 3: Wire up TEEVerifier with actual Nitro verifier address
        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(teeProxy);
        teeVerifier.setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier(nitroVerifier));

        // Step 4: Optionally register guardians
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0)) {
                teeVerifier.addGuardian(guardians[i]);
                console2.log("Added guardian:", guardians[i]);
            }
        }
    }

    function run() external {
        address nitroEnclaveVerifier = vm.envAddress("NITRO_ENCLAVE_VERIFIER");
        require(
            nitroEnclaveVerifier != address(0),
            "NITRO_ENCLAVE_VERIFIER environment variable not set or invalid"
        );

        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // Optional guardian addresses (comma-separated), e.g. GUARDIANS=0xAAA,0xBBB
        address[] memory emptyGuardians = new address[](0);
        address[] memory guardians = vm.envOr("GUARDIANS", ",", emptyGuardians);

        vm.startBroadcast();

        (address teeProxy, address teeImpl, address nitroVerifier) =
            deploy(proxyAdminOwner, nitroEnclaveVerifier, guardians);

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory json = "deployment";
        vm.serializeAddress(json, "teeVerifierImplementation", teeImpl);
        vm.serializeAddress(json, "teeVerifierProxy", teeProxy);
        string memory finalJson = vm.serializeAddress(json, "nitroVerifier", nitroVerifier);
        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-all-tee-verifiers.json"));

        string memory teeJson = "tee";
        vm.serializeAddress(teeJson, "implementation", teeImpl);
        string memory teeFinalJson = vm.serializeAddress(teeJson, "proxy", teeProxy);
        vm.writeJson(teeFinalJson, string.concat(dir, "/", chainId, "-espresso-tee-verifier.json"));

        string memory nitroFinalJson = vm.serializeAddress("nitro", "nitroVerifier", nitroVerifier);
        vm.writeJson(nitroFinalJson, string.concat(dir, "/", chainId, "-nitro-verifier.json"));
    }
}
