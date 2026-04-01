// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "@espresso-tee/EspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "@espresso-tee/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "@espresso-tee/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "@espresso-tee/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "@espresso-tee/interface/IEspressoNitroTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployAllTEEVerifiers
 * @notice Deploys all three TEE verifier contracts in a single transaction batch.
 *         SGX and Nitro verifiers are non-proxy contracts.
 *         EspressoTEEVerifier is deployed behind a TransparentUpgradeableProxy.
 *
 *      Deployment order:
 *      1. Deploy EspressoTEEVerifier proxy (with zero placeholder addresses for SGX/Nitro)
 *      2. Deploy EspressoSGXTEEVerifier with the actual TEEVerifier proxy address
 *      3. Deploy EspressoNitroTEEVerifier with the actual TEEVerifier proxy address
 *      4. Update EspressoTEEVerifier with the actual SGX and Nitro addresses
 *
 * @dev deploy() does not set guardians. run() optionally sets them via the GUARDIANS env var.
 *      To add a guardian after deployment:
 *      cast send <TEE_VERIFIER_PROXY> "addGuardian(address)" <GUARDIAN_ADDR> \
 *        --private-key $PRIVATE_KEY --rpc-url $RPC_URL
 */
contract DeployAllTEEVerifiers is Script {
    /**
     * @param proxyAdminOwner      Address that will own the auto-deployed ProxyAdmin.
     * @param quoteVerifier        Address of the SGX quote verifier (from Automata).
     * @param nitroEnclaveVerifier Address of the AWS Nitro enclave verifier.
     * @return teeProxy      Address of the deployed EspressoTEEVerifier proxy.
     * @return teeImpl       Address of the deployed EspressoTEEVerifier implementation.
     * @return sgxVerifier   Address of the deployed EspressoSGXTEEVerifier.
     * @return nitroVerifier Address of the deployed EspressoNitroTEEVerifier.
     */
    function deploy(address proxyAdminOwner, address quoteVerifier, address nitroEnclaveVerifier)
        public
        returns (address teeProxy, address teeImpl, address sgxVerifier, address nitroVerifier)
    {
        require(proxyAdminOwner != address(0), "proxyAdminOwner cannot be zero");
        // Step 1: Deploy TEEVerifier with zero placeholder addresses for SGX/Nitro
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log("TEEVerifier implementation deployed at:", address(teeVerifierImpl));

        TransparentUpgradeableProxy teeVerifierProxy = new TransparentUpgradeableProxy(
            address(teeVerifierImpl),
            proxyAdminOwner,
            abi.encodeWithSelector(
                EspressoTEEVerifier.initialize.selector,
                proxyAdminOwner,
                IEspressoSGXTEEVerifier(address(0)),
                IEspressoNitroTEEVerifier(address(0))
            )
        );
        console2.log("TEEVerifier proxy deployed at:", address(teeVerifierProxy));

        teeProxy = address(teeVerifierProxy);
        teeImpl = address(teeVerifierImpl);

        // Step 2: Deploy SGXVerifier pointing to TEEVerifier
        EspressoSGXTEEVerifier sgx = new EspressoSGXTEEVerifier(teeProxy, quoteVerifier);
        console2.log("SGXVerifier deployed at:", address(sgx));
        sgxVerifier = address(sgx);

        // Step 3: Deploy NitroVerifier pointing to TEEVerifier
        EspressoNitroTEEVerifier nitro =
            new EspressoNitroTEEVerifier(teeProxy, nitroEnclaveVerifier);
        console2.log("NitroVerifier deployed at:", address(nitro));
        nitroVerifier = address(nitro);

        // Step 4: Wire up TEEVerifier with actual subverifier addresses
        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(teeProxy);
        teeVerifier.setEspressoSGXTEEVerifier(IEspressoSGXTEEVerifier(sgxVerifier));
        teeVerifier.setEspressoNitroTEEVerifier(IEspressoNitroTEEVerifier(nitroVerifier));
    }

    function run() external {
        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        require(
            quoteVerifierAddr != address(0),
            "SGX_QUOTE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        address nitroEnclaveVerifier = vm.envAddress("NITRO_ENCLAVE_VERIFIER");
        require(
            nitroEnclaveVerifier != address(0),
            "NITRO_ENCLAVE_VERIFIER environment variable not set or invalid"
        );

        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // Optional guardian addresses (comma-separated)
        address[] memory emptyGuardians = new address[](0);
        address[] memory guardians = vm.envOr("GUARDIANS", ",", emptyGuardians);

        vm.startBroadcast();

        (address teeProxy, address teeImpl, address sgxVerifier, address nitroVerifier) =
            deploy(proxyAdminOwner, quoteVerifierAddr, nitroEnclaveVerifier);

        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(teeProxy);
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0)) {
                teeVerifier.addGuardian(guardians[i]);
                console2.log("Added guardian:", guardians[i]);
            }
        }

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        string memory json = "deployment";
        vm.serializeAddress(json, "teeVerifierImplementation", teeImpl);
        vm.serializeAddress(json, "teeVerifierProxy", teeProxy);
        vm.serializeAddress(json, "sgxVerifier", sgxVerifier);
        string memory finalJson = vm.serializeAddress(json, "nitroVerifier", nitroVerifier);
        vm.writeJson(finalJson, string.concat(dir, "/", chainId, "-all-tee-verifiers.json"));

        string memory teeJson = "tee";
        vm.serializeAddress(teeJson, "implementation", teeImpl);
        string memory teeFinalJson = vm.serializeAddress(teeJson, "proxy", teeProxy);
        vm.writeJson(teeFinalJson, string.concat(dir, "/", chainId, "-espresso-tee-verifier.json"));

        string memory sgxFinalJson = vm.serializeAddress("sgx", "sgxVerifier", sgxVerifier);
        vm.writeJson(sgxFinalJson, string.concat(dir, "/", chainId, "-sgx-verifier.json"));

        string memory nitroFinalJson = vm.serializeAddress("nitro", "nitroVerifier", nitroVerifier);
        vm.writeJson(nitroFinalJson, string.concat(dir, "/", chainId, "-nitro-verifier.json"));
    }
}
