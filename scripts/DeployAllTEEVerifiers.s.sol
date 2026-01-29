pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "src/EspressoTEEVerifier.sol";
import {EspressoSGXTEEVerifier} from "src/EspressoSGXTEEVerifier.sol";
import {EspressoNitroTEEVerifier} from "src/EspressoNitroTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "src/interface/IEspressoNitroTEEVerifier.sol";
import {INitroEnclaveVerifier} from "aws-nitro-enclave-attestation/interfaces/INitroEnclaveVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeployAllTEEVerifiers
 * @notice Deploys all three TEE verifier contracts (EspressoTEEVerifier, EspressoSGXTEEVerifier, EspressoNitroTEEVerifier)
 *         using OpenZeppelin v5.x Transparent Proxy pattern in a single transaction batch.
 *
 *      Deployment order:
 *      1. Deploy EspressoTEEVerifier proxy (with placeholder addresses for SGX/Nitro)
 *      2. Deploy EspressoSGXTEEVerifier proxy (with TEEVerifier proxy address)
 *      3. Deploy EspressoNitroTEEVerifier proxy (with TEEVerifier proxy address)
 *      4. Update TEEVerifier with actual SGX and Nitro proxy addresses
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

        // ============ Step 1: Deploy TEEVerifier ============
        // Deploy implementation
        EspressoTEEVerifier teeVerifierImpl = new EspressoTEEVerifier();
        console2.log(
            "TEEVerifier implementation deployed at:",
            address(teeVerifierImpl)
        );

        // Deploy proxy with placeholder addresses (will be updated after SGX/Nitro deployment)
        // Note: Initialize accepts zero addresses, they will be set properly after SGX/Nitro deployment
        bytes memory teeInitData = abi.encodeWithSelector(
            EspressoTEEVerifier.initialize.selector,
            proxyAdminOwner,
            IEspressoSGXTEEVerifier(address(0)), // placeholder
            IEspressoNitroTEEVerifier(address(0)) // placeholder
        );

        TransparentUpgradeableProxy teeVerifierProxy = new TransparentUpgradeableProxy(
                address(teeVerifierImpl),
                proxyAdminOwner,
                teeInitData
            );
        console2.log(
            "TEEVerifier proxy deployed at:",
            address(teeVerifierProxy)
        );

        EspressoSGXTEEVerifier sgxVerifierImpl = new EspressoSGXTEEVerifier();
        console2.log(
            "SGXVerifier implementation deployed at:",
            address(sgxVerifierImpl)
        );

        // Deploy proxy with TEEVerifier proxy address
        bytes memory sgxInitData = abi.encodeWithSelector(
            EspressoSGXTEEVerifier.initialize.selector,
            address(teeVerifierProxy),
            quoteVerifierAddr
        );

        TransparentUpgradeableProxy sgxVerifierProxy = new TransparentUpgradeableProxy(
                address(sgxVerifierImpl),
                proxyAdminOwner,
                sgxInitData
            );
        console2.log(
            "SGXVerifier proxy deployed at:",
            address(sgxVerifierProxy)
        );

        EspressoNitroTEEVerifier nitroVerifierImpl = new EspressoNitroTEEVerifier();
        console2.log(
            "NitroVerifier implementation deployed at:",
            address(nitroVerifierImpl)
        );

        bytes memory nitroInitData = abi.encodeWithSelector(
            EspressoNitroTEEVerifier.initialize.selector,
            address(teeVerifierProxy),
            INitroEnclaveVerifier(nitroEnclaveVerifier)
        );

        TransparentUpgradeableProxy nitroVerifierProxy = new TransparentUpgradeableProxy(
                address(nitroVerifierImpl),
                proxyAdminOwner,
                nitroInitData
            );
        console2.log(
            "NitroVerifier proxy deployed at:",
            address(nitroVerifierProxy)
        );

        //  Update TEEVerifier with actual verifier addresses
        EspressoTEEVerifier teeVerifier = EspressoTEEVerifier(
            address(teeVerifierProxy)
        );
        teeVerifier.setEspressoSGXTEEVerifier(
            IEspressoSGXTEEVerifier(address(sgxVerifierProxy))
        );
        teeVerifier.setEspressoNitroTEEVerifier(
            IEspressoNitroTEEVerifier(address(nitroVerifierProxy))
        );
        console2.log(
            "TEEVerifier updated with SGX and Nitro verifier addresses"
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
