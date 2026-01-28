pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

/**
 * @title DeploySGXTEEVerifier
 * @notice Deploys EspressoSGXTEEVerifier using OpenZeppelin v5.x Transparent Proxy pattern
 * @dev In v5.x, TransparentUpgradeableProxy automatically deploys a ProxyAdmin internally.
 *      The initialOwner passed becomes the owner of the auto-deployed ProxyAdmin.
 */
contract DeploySGXTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        require(
            quoteVerifierAddr != address(0),
            "SGX_QUOTE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        // TEE_VERIFIER_ADDRESS is the address of the main EspressoTEEVerifier proxy
        // This is used to set the teeVerifier in the SGXTEEVerifier which controls admin functions
        address teeVerifierAddress = vm.envAddress("TEE_VERIFIER_ADDRESS");
        require(
            teeVerifierAddress != address(0),
            "TEE_VERIFIER_ADDRESS environment variable not set or invalid"
        );

        // PROXY_ADMIN_OWNER is the address that will own the auto-deployed ProxyAdmin
        // If not set, defaults to msg.sender
        address proxyAdminOwner = vm.envOr("PROXY_ADMIN_OWNER", msg.sender);

        // 1. Deploy SGX Verifier implementation
        EspressoSGXTEEVerifier sgxVerifierImpl = new EspressoSGXTEEVerifier();
        console2.log(
            "SGXVerifier implementation deployed at:",
            address(sgxVerifierImpl)
        );

        // 2. Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            EspressoSGXTEEVerifier.initialize.selector,
            teeVerifierAddress,
            quoteVerifierAddr
        );

        // 3. Deploy TransparentUpgradeableProxy (v5.x pattern)
        // ProxyAdmin is automatically deployed internally with proxyAdminOwner as its owner
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(sgxVerifierImpl),
            proxyAdminOwner,
            initData
        );
        console2.log("SGXVerifier proxy deployed at:", address(proxy));

        vm.stopBroadcast();

        // Save deployment artifacts (outside of broadcast to avoid gas costs)
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write deployment addresses
        string memory json = "sgx";
        vm.serializeAddress(json, "implementation", address(sgxVerifierImpl));
        string memory finalJson = vm.serializeAddress(
            json,
            "proxy",
            address(proxy)
        );

        vm.writeJson(
            finalJson,
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );
    }
}
