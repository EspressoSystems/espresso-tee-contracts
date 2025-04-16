import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {EspressoSGXTEEVerifier} from "src/EspressoSGXTEEVerifier.sol";
import {IEspressoSGXTEEVerifier} from "src/interface/IEspressoSGXTEEVerifier.sol";

contract DeploySGXTEEVerifier is Script {
    bytes32 constant SGX_VERIFIER_SALT = keccak256("espresso.sgxverifier.v1");

    function run() external {
        vm.startBroadcast();
        bytes32 enclaveHash = vm.envBytes32("SGX_ENCLAVE_HASH");
        address quoteVerifierAddr = vm.envAddress("SGX_QUOTE_VERIFIER_ADDRESS");
        // 2. Deploy SGX Verifier
        IEspressoSGXTEEVerifier sgxVerifier = new EspressoSGXTEEVerifier{salt: SGX_VERIFIER_SALT}(
            enclaveHash,
            quoteVerifierAddr
        );
        console2.log("SGXVerifier deployed at:", address(sgxVerifier));

        // Save deployment artifacts
        string memory chainId = vm.toString(block.chainid);
        string memory dir = string.concat(vm.projectRoot(), "/deployments");

        // Write SGX address
        vm.writeJson(
            vm.serializeAddress("", "EspressoSGXTEEVerifier", address(sgxVerifier)),
            string.concat(dir, "/", chainId, "-sgx-verifier.json")
        );

        vm.stopBroadcast();
    }
}