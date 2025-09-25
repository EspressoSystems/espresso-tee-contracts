package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ethereum/go-ethereum/accounts/abi/abigen"
)

type HardHatArtifact struct {
	Format       string        `json:"_format"`
	ContractName string        `json:"contractName"`
	SourceName   string        `json:"sourceName"`
	Abi          []interface{} `json:"abi"`
	Bytecode     string        `json:"bytecode"`
}

type FoundryBytecode struct {
	Object string `json:"object"`
}

type FoundryArtifact struct {
	Abi      []interface{}   `json:"abi"`
	Bytecode FoundryBytecode `json:"bytecode"`
}

type moduleInfo struct {
	contractNames []string
	abis          []string
	bytecodes     []string
}

func (m *moduleInfo) addArtifact(artifact HardHatArtifact) {
	abi, err := json.Marshal(artifact.Abi)
	if err != nil {
		log.Fatal(err)
	}
	m.contractNames = append(m.contractNames, artifact.ContractName)
	m.abis = append(m.abis, string(abi))
	m.bytecodes = append(m.bytecodes, artifact.Bytecode)
}

func main() {
	//Get the file that called this so we can fetch the directory of the project.
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("bad path")
	}
	root := filepath.Dir(filename)
	parent := filepath.Dir(root)
	//After we have the parent directory, we can make the modules and then grab the relevant espresso information.
	modules := make(map[string]*moduleInfo)
	modules, err := GenerateEspressoTEEContracts(modules, parent)
	if err != nil {
		log.Fatal("unable to get modules for EspressoTEEVerifier contracts")
	}
	for module, info := range modules {

		code, err := abigen.Bind(
			info.contractNames,
			info.abis,
			info.bytecodes,
			nil,
			module,
			nil,
			nil,
		)
		if err != nil {
			log.Fatal(err)
		}

		folder := filepath.Join(root, "go", module)

		err = os.MkdirAll(folder, 0o755)
		if err != nil {
			log.Fatal(err)
		}

		// write to the parent dir to have the bindings presented in a location in the repo with no go.mod as a parent or sibling file.
		// This helps prevent go mod tidy, and the compiler getting confused when attempting to find the package if it is
		// included in another project as a submodule.

		/*
			#nosec G306
			This file contains no private information so the permissions can be lenient
		*/
		err = os.WriteFile(filepath.Join(parent, module, module+".go"), []byte(code), 0o644)
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Println("successfully generated go abi files")
}

func GenerateEspressoTEEContracts(modules map[string]*moduleInfo, parent string) (map[string]*moduleInfo, error) {
	filePathsEspressoTeeContracts, err := filepath.Glob(filepath.Join(parent, "out", "*.sol", "*.json"))
	if err != nil {
		return modules, fmt.Errorf("failed to get path for espresso tee contracts: %w", err)
	}

	espressoTEEContractsInfo := modules["espressogen"]
	if espressoTEEContractsInfo == nil {
		espressoTEEContractsInfo = &moduleInfo{}
		modules["espressogen"] = espressoTEEContractsInfo
	}

	for _, path := range filePathsEspressoTeeContracts {
		_, file := filepath.Split(path)
		//Get the name of the file, sans file format (Currently ".json" for hardhat artifacts)
		name := file[:len(file)-5]

		data, err := os.ReadFile(path)
		if err != nil {
			return modules, fmt.Errorf("could not read %s for contract %s: %w", path, name, err)
		}
		artifact := FoundryArtifact{}
		if err := json.Unmarshal(data, &artifact); err != nil {
			return modules, fmt.Errorf("failed to parse espresso contract %s: %w", name, err)
		}
		espressoTEEContractsInfo.addArtifact(HardHatArtifact{
			ContractName: name,
			Abi:          artifact.Abi,
			Bytecode:     artifact.Bytecode.Object,
		})
	}
	return modules, nil
}
