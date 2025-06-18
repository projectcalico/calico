// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// gomodder is a utility to verify go module, like ensuring all go modules in the project have the same go version and
// modules adhere to specific import restrictions.

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"
	"gopkg.in/yaml.v3"
)

const (
	goModFileName  = "go.mod"
	configFileName = "gomodder_config.yaml"
)

type config struct {
	RequireExplicitDirectDependencies bool                `yaml:"requireExplicitDirectDependencies"`
	AllowedDirectDependencies         []string            `yaml:"allowedDirectDependencies"`
	allowedDirectDependenciesMap      map[string]struct{} `yaml:"-"`
	RestrictedDirectDependencies      []string            `yaml:"restrictedDirectDependencies"`
	restrictedDirectDependenciesMap   map[string]struct{} `yaml:"-"`
}

func (cfg config) directDependencyAllowed(dep string) error {
	if cfg.RequireExplicitDirectDependencies {
		if _, ok := cfg.allowedDirectDependenciesMap[dep]; !ok {
			return fmt.Errorf("'%s' is not allowed as a direct (requireExplicitDirectDependencies is set), either remove the import or add it to the 'allowedDirectDependencies' list", dep)
		}
	}

	if _, ok := cfg.restrictedDirectDependenciesMap[dep]; ok {
		return fmt.Errorf("'%s' is a restricted direct dependency, either remove the import or remove it from the 'restrictedDirectDependencies' list", dep)
	}

	return nil
}

func main() {
	runVerifyGoModImportRestrictions()
}

func runVerifyGoModImportRestrictions() {
	modFolders, err := findGoModuleFolders()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error finding go module folders: %v\n", err)
		os.Exit(1)
	}

	// Get the root go.mod so we can use it for the standard to compare against other go.mods (like for version matching).
	rootGoMod, err := getGoMod(".")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error parsing root go.mod: %v\n", err)
		os.Exit(1)
	}

	cfg, err := getConfig(".")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error getting config: %v\n", err)
		os.Exit(1)
	}

	// Verify the root go.mod first.
	if err := verifyModuleImports(cfg, rootGoMod); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to verify module imports for '.': %v\n", err)
		os.Exit(1)
	}

	for _, folder := range modFolders {
		fmt.Printf("Verifying go module in '%s' ...\n", folder)
		goMod, err := getGoMod(folder)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing go.mod: %v\n", err)
			os.Exit(1)
		}

		cfg, err := getConfig(folder)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error getting config: %v\n", err)
			os.Exit(1)
		}

		if goMod.Go.Version != rootGoMod.Go.Version {
			_, _ = fmt.Fprintf(os.Stderr, "Error: go.mod version in '%s' ('%s') does not match root go.mod version ('%s')\n", folder, goMod.Go.Version, rootGoMod.Go.Version)
			os.Exit(1)
		}

		if err := verifyModuleImports(cfg, goMod); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to verify module imports for: %v\n", err)
			os.Exit(1)
		}
	}
}

// verifyModuleImports checks module dependencies against allowed and restricted lists and returns an error if any violations exist.
// It looks for files named after the allowedGoImportsFileName and restrictedGoImportsFileName constants in the given folder,
// and if found, it uses the contents of those files to restrict what imports are allowed in the given goMod.
//
// Rules follow:
// - If allowedDependencies are found, then all direct dependencies in the goMod file must be in this list
// - If restrictedDependencies are found, then all direct dependencies must not be in this list
func verifyModuleImports(cfg config, goMod *modfile.File) error {
	for _, req := range goMod.Require {
		// If you want all dependencies, remove this condition
		if !req.Indirect {
			if err := cfg.directDependencyAllowed(req.Mod.Path); err != nil {
				return err
			}
		}
	}

	return nil
}

func getConfig(modFolder string) (config, error) {
	var cfg config

	configPath := filepath.Join(modFolder, configFileName)
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return cfg, fmt.Errorf("failed to read config file %s: %w\n", configPath, err)
		}
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("invalid gomodder config found at %s: %w \n", configPath, err)
		}
	}

	cfg.allowedDirectDependenciesMap = make(map[string]struct{})
	cfg.restrictedDirectDependenciesMap = make(map[string]struct{})

	for _, dep := range cfg.AllowedDirectDependencies {
		cfg.allowedDirectDependenciesMap[dep] = struct{}{}
	}
	for _, dep := range cfg.RestrictedDirectDependencies {
		cfg.restrictedDirectDependenciesMap[dep] = struct{}{}
	}

	return cfg, nil
}

func getGoMod(folder string) (*modfile.File, error) {
	data, err := os.ReadFile(filepath.Join(folder, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("error reading go.mod: %w\n", err)
	}
	goMod, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("Error parsing go.mod: %w\n", err)
	}
	return goMod, nil
}

func findGoModuleFolders() ([]string, error) {
	root := "."
	var goModFolders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if path == root {
			return nil
		}

		if info.IsDir() {
			modPath := filepath.Join(path, goModFileName)
			if _, err := os.Stat(modPath); err == nil {
				goModFolders = append(goModFolders, path)
			}
		}
		return nil
	})

	return goModFolders, err
}
