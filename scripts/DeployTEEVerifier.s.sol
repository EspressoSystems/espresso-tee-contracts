pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoTEEVerifier} from "src/EspressoTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "../src/interface/IEspressoSGXTEEVerifier.sol";
import {IEspressoNitroTEEVerifier} from "../src/interface/IEspressoNitroTEEVerifier.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract DeployTEEVerifier is Script {
    function run() external {
        vm.startBroadcast();

        address sgxVerifierAddr = vm.envAddress("SGX_VERIFIER_ADDRESS");
        address nitroVerifierAddr = vm.envAddress("NITRO_VERIFIER_ADDRESS");

        require(
            sgxVerifierAddr != address(0),
            "SGX_VERIFIER_ADDRESS environment variable not set or invalid"
        );
        require(
            nitroVerifierAddr != address(0),
            "nitroVerifierAddr environment variable not set or invalid"
        );

        IEspressoSGXTEEVerifier sgxVerifier = IEspressoSGXTEEVerifier(
            sgxVerifierAddr
        );
        IEspressoNitroTEEVerifier nitroVerifier = IEspressoNitroTEEVerifier(
            nitroVerifierAddr
        );

        // Get the deployer address (msg.sender) to use as initial owner
        address initialOwner = msg.sender;
        console2.log("Deploying with initial owner:", initialOwner);

        // Deploy implementation contract
        EspressoTEEVerifier implementation = new EspressoTEEVerifier();
        console2.log("Implementation deployed at:", address(implementation));

        // Prepare initialization data
        bytes memory initData = abi.encodeWithSelector(
            EspressoTEEVerifier.initialize.selector,
            initialOwner,
            sgxVerifier,
            nitroVerifier
        );

        // Deploy proxy and initialize
        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(
            address(implementation),
            initialOwner,
            initData
        );
        EspressoTEEVerifier verifier = EspressoTEEVerifier(address(proxy));
        console2.log("Proxy (TEEVerifier) deployed at:", address(proxy));
        console2.log("Owner:", verifier.owner());

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write both implementation and proxy addresses
        string memory json = "";
        json = vm.serializeAddress(
            "",
            "Implementation",
            address(implementation)
        );
        json = vm.serializeAddress("", "Proxy", address(proxy));
        json = vm.serializeAddress(
            "",
            "EspressoTEEVerifier",
            address(verifier)
        );
        json = vm.serializeAddress("", "Owner", initialOwner);

        vm.writeJson(
            json,
            string.concat(dir, "/", chainId, "-espresso-tee-verifier.json")
        );

        vm.stopBroadcast();
    }
}
