pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "@espresso-tee/EspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "@espresso-tee/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "@espresso-tee/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "@espresso-tee/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "@espresso-tee/interface/IEspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployAllTEEVerifiers
 * @notice Deploys all three TEE verifier contracts (EspressoTEEVerifier, EspressoSGXTEEVerifier, EspressoNitroTEEVerifier)
 *         using OpenZeppelin v5.x Transparent Proxy pattern in a single transaction batch.
 *
 *      Deployment order:
 *      1. Deploy EspressoSGXTEEVerifier proxy (with precomputed TEEVerifier proxy address)
 *      2. Deploy EspressoNitroTEEVerifier proxy (with precomputed TEEVerifier proxy address)
 *      3. Deploy EspressoTEEVerifier proxy (with actual SGX and Nitro proxy addresses)
 */
contract DeployAllTEEVerifiers is Script {
    // ERC1967 admin slot: keccak256("eip1967.proxy.admin") - 1
    bytes32 internal constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

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

        // Owner address for the auto-deployed ProxyAdmin contracts
        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // Optional guardian addresses (comma-separated)
        // Uses Forge's built-in envOr with comma delimiter to parse address arrays
        address[] memory emptyGuardians = new address[](0);
        address[] memory guardians = vm.envOr("GUARDIANS", ",", emptyGuardians);

        // Precompute TEE verifier proxy address — 5 nonces ahead from msg.sender:
        // SGX impl, SGX proxy, Nitro impl, Nitro proxy, TEE impl → TEE proxy
        address teeVerifierAddr =
            vm.computeCreateAddress(msg.sender, vm.getNonce(msg.sender) + 5);

        // ============ Step 1: Deploy SGXVerifier ============
        EspressoSGXTEEVerifier sgxVerifierImpl = new EspressoSGXTEEVerifier();
        console2.log("SGXVerifier implementation deployed at:", address(sgxVerifierImpl));

        TransparentUpgradeableProxy sgxVerifierProxy = new TransparentUpgradeableProxy(
            address(sgxVerifierImpl),
            proxyAdminOwner,
            abi.encodeWithSelector(
                EspressoSGXTEEVerifier.initialize.selector,
                teeVerifierAddr,
                quoteVerifierAddr
            )
        );
        console2.log("SGXVerifier proxy deployed at:", address(sgxVerifierProxy));

        // ============ Step 2: Deploy NitroVerifier ============
        EspressoNitroTEEVerifier nitroVerifierImpl = new EspressoNitroTEEVerifier();
        console2.log("NitroVerifier implementation deployed at:", address(nitroVerifierImpl));

        TransparentUpgradeableProxy nitroVerifierProxy = new TransparentUpgradeableProxy(
            address(nitroVerifierImpl),
            proxyAdminOwner,
            abi.encodeWithSelector(
                EspressoNitroTEEVerifier.initialize.selector,
                teeVerifierAddr,
                INitroEnclaveVerifier(nitroEnclaveVerifier)
            )
        );
        console2.log("NitroVerifier proxy deployed at:", address(nitroVerifierProxy));

        // ============ Step 3: Deploy TEEVerifier with real subverifier addresses ============
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log("TEEVerifier implementation deployed at:", address(teeVerifierImpl));

        TransparentUpgradeableProxy teeVerifierProxy = new TransparentUpgradeableProxy(
            address(teeVerifierImpl),
            proxyAdminOwner,
            abi.encodeWithSelector(
                EspressoTEEVerifier.initialize.selector,
                proxyAdminOwner,
                IEspressoSGXTEEVerifier(address(sgxVerifierProxy)),
                IEspressoNitroTEEVerifier(address(nitroVerifierProxy))
            )
        );
        console2.log("TEEVerifier proxy deployed at:", address(teeVerifierProxy));

        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(address(teeVerifierProxy));

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

        // SGX Verifier addresses
        vm.serializeAddress(
            json,
            "sgxVerifierImplementation",
            address(sgxVerifierImpl)
        );
        vm.serializeAddress(
            json,
            "sgxVerifierProxy",
            address(sgxVerifierProxy)
        );

        // Nitro Verifier addresses
        vm.serializeAddress(
            json,
            "nitroVerifierImplementation",
            address(nitroVerifierImpl)
        );
        string memory finalJson = vm.serializeAddress(
            json,
            "nitroVerifierProxy",
            address(nitroVerifierProxy)
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

        string memory sgxJson = "sgx";
        vm.serializeAddress(
            sgxJson,
            "implementation",
            address(sgxVerifierImpl)
        );
        string memory sgxFinalJson = vm.serializeAddress(
            sgxJson,
            "proxy",
            address(sgxVerifierProxy)
        );
        vm.writeJson(
            sgxFinalJson,
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );

        string memory nitroJson = "nitro";
        vm.serializeAddress(
            nitroJson,
            "implementation",
            address(nitroVerifierImpl)
        );
        string memory nitroFinalJson = vm.serializeAddress(
            nitroJson,
            "proxy",
            address(nitroVerifierProxy)
        );
        vm.writeJson(
            nitroFinalJson,
            string.concat(dir, "/", chainId, "-nitro-verifier.json")
        );
    }
}
