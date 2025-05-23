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
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

const (
	goModFileName = "go.mod"

	allowedGoImportsFileName    = "allowedgoimports.txt"
	restrictedGoImportsFileName = "restrictedgoimports.txt"
)

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

	// Verify the root go.mod first.
	if err := verifyModuleImports(".", rootGoMod); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error verifying module imports: %v\n", err)
		os.Exit(1)
	}

	for _, folder := range modFolders {
		fmt.Printf("Verifying go mod in '%s' ...\n", folder)
		goMod, err := getGoMod(folder)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error parsing go.mod: %v\n", err)
			os.Exit(1)
		}

		if goMod.Go.Version != rootGoMod.Go.Version {
			_, _ = fmt.Fprintf(os.Stderr, "Error: go.mod version in '%s' ('%s') does not match root go.mod version ('%s')\n", folder, goMod.Go.Version, rootGoMod.Go.Version)
			os.Exit(1)
		}

		if err := verifyModuleImports(folder, goMod); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error verifying module imports: %v\n", err)
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
func verifyModuleImports(folder string, goMod *modfile.File) error {
	fmt.Printf("Verifying module imports in '%s' ...\n", folder)

	allowedDependencies, err := getDependencyMap(folder, allowedGoImportsFileName)
	if err != nil {
		return fmt.Errorf("error getting allowed dependencies: %w", err)
	}

	restrictedDependencies, err := getDependencyMap(folder, restrictedGoImportsFileName)
	if err != nil {
		return fmt.Errorf("error getting restricted dependencies: %w", err)
	}

	if allowedDependencies != nil || restrictedDependencies != nil {
		fmt.Println("Verifying allowed and restricted dependencies...")
		for _, req := range goMod.Require {
			// If you want all dependencies, remove this condition
			if !req.Indirect {
				if allowedDependencies != nil {
					if _, ok := allowedDependencies[req.Mod.Path]; !ok {
						return errors.New(fmt.Sprintf("'%s' is not allowed as a direct dependency. Either remove the import or add it to the 'allowedgodependencies.txt' file.\n", req.Mod.Path))
					}
				}
				if restrictedDependencies != nil {
					if _, ok := restrictedDependencies[req.Mod.Path]; ok {
						return errors.New(fmt.Sprintf("'%s' is a restricted direct dependency. Either remove the import or remove it from the 'restrictedgodependencies.txt' file.\n", req.Mod.Path))
					}
				}
			}
		}
	}

	fmt.Print("Module imports verified\n")
	return nil
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

func getDependencyMap(folder string, fileName string) (map[string]struct{}, error) {
	file, err := os.Open(filepath.Join(folder, fileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	depMap := make(map[string]struct{})

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// Trim whitespace and skip empty lines
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			depMap[line] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return depMap, nil
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
