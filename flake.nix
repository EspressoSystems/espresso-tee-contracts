{
  description = "Espresso TEE Contracts - Solidity contracts for verifying TEE attestations";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    foundry.url = "github:shazow/foundry.nix/monthly"; # Use monthly branch for permanent releases
  };

  outputs = { self, nixpkgs, flake-utils, foundry }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ foundry.overlay ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Foundry toolchain (forge, cast, anvil, chisel)
            foundry-bin

            # Solidity compiler
            solc

            # Useful development tools
            git
          ];

          shellHook = ''
            echo "🔧 Espresso TEE Contracts Development Environment"
            echo "================================================"
            echo ""
            echo "Available commands:"
            echo "  forge build    - Build the contracts"
            echo "  forge test     - Run tests"
            echo "  forge fmt      - Format Solidity code"
            echo "  forge snapshot - Generate gas snapshots"
            echo "  anvil          - Start local Ethereum node"
            echo "  cast           - Ethereum CLI tool"
            echo ""
            echo "Foundry version: $(forge --version | head -n1)"
            echo "Solc version: $(solc --version | head -n1)"
            echo ""
          '';
        };

        # For backwards compatibility
        devShell = self.devShells.${system}.default;
      }
    );
}

