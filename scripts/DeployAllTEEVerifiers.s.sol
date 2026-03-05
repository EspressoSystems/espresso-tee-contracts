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
 *      1. Deploy EspressoSGXTEEVerifier with precomputed TEEVerifier proxy address
 *      2. Deploy EspressoNitroTEEVerifier with precomputed TEEVerifier proxy address
 *      3. Deploy EspressoTEEVerifier proxy (with actual SGX and Nitro addresses)
 */
contract DeployAllTEEVerifiers is Script {
    function run() external {
        vm.startBroadcast();

        // External verifier addresses (from Automata)
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

        // Owner address for the auto-deployed ProxyAdmin contract
        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // Optional guardian addresses (comma-separated)
        // Uses Forge's built-in envOr with comma delimiter to parse address arrays
        address[] memory emptyGuardians = new address[](0);
        address[] memory guardians = vm.envOr("GUARDIANS", ",", emptyGuardians);

        // Precompute TEE verifier proxy address — 3 nonces ahead from msg.sender:
        // SGX, Nitro, TEE impl → TEE proxy
        address teeVerifierAddr =
            vm.computeCreateAddress(msg.sender, vm.getNonce(msg.sender) + 3);

        // ============ Step 1: Deploy SGXVerifier ============
        EspressoSGXTEEVerifier sgxVerifier =
            new EspressoSGXTEEVerifier(teeVerifierAddr, quoteVerifierAddr);
        console2.log(
            "SGXVerifier deployed at:",
            address(sgxVerifier)
        );

        // ============ Step 2: Deploy NitroVerifier ============
        EspressoNitroTEEVerifier nitroVerifier =
            new EspressoNitroTEEVerifier(teeVerifierAddr, nitroEnclaveVerifier);
        console2.log(
            "NitroVerifier deployed at:",
            address(nitroVerifier)
        );

        // ============ Step 3: Deploy TEEVerifier with real subverifier addresses ============
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log(
            "TEEVerifier implementation deployed at:",
            address(teeVerifierImpl)
        );

        TransparentUpgradeableProxy teeVerifierProxy = new TransparentUpgradeableProxy(
                address(teeVerifierImpl),
                proxyAdminOwner,
                abi.encodeWithSelector(
                    EspressoTEEVerifier.initialize.selector,
                    proxyAdminOwner,
                    IEspressoSGXTEEVerifier(address(sgxVerifier)),
                    IEspressoNitroTEEVerifier(address(nitroVerifier))
                )
            );
        console2.log(
            "TEEVerifier proxy deployed at:",
            address(teeVerifierProxy)
        );

        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(
            address(teeVerifierProxy)
        );

        // Add guardians if provided
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] != address(0)) {
                teeVerifier.addGuardian(guardians[i]);
                console2.log("Added guardian:", guardians[i]);
            }
        }

        vm.stopBroadcast();

        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write combined deployment JSON
        string memory json = "deployment";

        // TEEVerifier addresses
        vm.serializeAddress(
            json,
            "teeVerifierImplementation",
            address(teeVerifierImpl)
        );
        vm.serializeAddress(
            json,
            "teeVerifierProxy",
            address(teeVerifierProxy)
        );

        // SGX Verifier address
        vm.serializeAddress(
            json,
            "sgxVerifier",
            address(sgxVerifier)
        );

        // Nitro Verifier address
        string memory finalJson = vm.serializeAddress(
            json,
            "nitroVerifier",
            address(nitroVerifier)
        );

        vm.writeJson(
            finalJson,
            string.concat(dir, "/", chainId, "-all-tee-verifiers.json")
        );

        string memory teeJson = "tee";
        vm.serializeAddress(
            teeJson,
            "implementation",
            address(teeVerifierImpl)
        );
        string memory teeFinalJson = vm.serializeAddress(
            teeJson,
            "proxy",
            address(teeVerifierProxy)
        );
        vm.writeJson(
            teeFinalJson,
            string.concat(dir, "/", chainId, "-espresso-tee-verifier.json")
        );

        string memory sgxFinalJson = vm.serializeAddress(
            "sgx",
            "sgxVerifier",
            address(sgxVerifier)
        );
        vm.writeJson(
            sgxFinalJson,
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );

        string memory nitroFinalJson = vm.serializeAddress(
            "nitro",
            "nitroVerifier",
            address(nitroVerifier)
        );
        vm.writeJson(
            nitroFinalJson,
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );
    }
}
