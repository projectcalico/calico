// Copyright (c) 2026 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package versions

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/tigera/operator/hack/release/internal/command"
	"go.yaml.in/yaml/v3"
)

const (
	configDir = "config"
	// CalicoConfigPath is the repo-relative path to the Calico versions config file.
	CalicoConfigPath = configDir + "/calico_versions.yml"
	// EnterpriseConfigPath is the repo-relative path to the Enterprise versions config file.
	EnterpriseConfigPath = configDir + "/enterprise_versions.yml"

	// MakeTargetGenVersionsCalico is the make target to regenerate Calico versions.
	MakeTargetGenVersionsCalico = "gen-versions-calico"
	// MakeTargetGenVersionsEnterprise is the make target to regenerate Enterprise versions.
	MakeTargetGenVersionsEnterprise = "gen-versions-enterprise"
)

// Patterns for components to exclude from version updates
var excludedComponentsPatterns = []string{
	`^coreos-.*`,
	`^eck-.*`,
}

// Versions holds the Calico and Enterprise release version strings.
type Versions struct {
	Calico     string
	Enterprise string
}

// ToMap returns a human-readable map of non-empty version strings keyed by product name.
func (v Versions) ToMap() map[string]string {
	result := make(map[string]string)
	if v.Calico != "" {
		result["Calico"] = v.Calico
	}
	if v.Enterprise != "" {
		result["Calico Enterprise"] = v.Enterprise
	}
	return result
}

// VersionConfig holds version, registry, and optional local CRD directory for one product.
type VersionConfig struct {
	Dir      string
	Version  string
	Registry string
}

// VersionsConfig holds configuration for generating both Calico and Enterprise versions.
type VersionsConfig struct {
	RepoRootDir string
	Calico      VersionConfig
	Enterprise  VersionConfig
}

// Generate updates the version config files and runs the appropriate make targets
// to regenerate derived files for the configured products.
func (vc *VersionsConfig) Generate() error {
	makeTargets := []string{"fix"}
	env := os.Environ()
	if vc.Calico.Version != "" {
		err := UpdateCalicoConfigVersion(vc.RepoRootDir, vc.Calico.Version)
		if err != nil {
			return err
		}
		makeTargets = append(makeTargets, MakeTargetGenVersionsCalico)
		// Set CALICO_CRDS_DIR if specified
		if crdsDir := vc.Calico.Dir; crdsDir != "" {
			logrus.Warnf("Using local Calico CRDs from %s", crdsDir)
			env = append(env, fmt.Sprintf("CALICO_CRDS_DIR=%s", crdsDir))
		}
	}
	if vc.Enterprise.Version != "" {
		err := UpdateEnterpriseConfigVersion(vc.RepoRootDir, vc.Enterprise.Version)
		if err != nil {
			return err
		}
		makeTargets = append(makeTargets, MakeTargetGenVersionsEnterprise)
		// Update registry for Enterprise
		if eRegistry := vc.Enterprise.Registry; eRegistry != "" {
			logrus.Debugf("Updating Enterprise registry to %s", eRegistry)
			if err := ModifyComponentImageConfig(vc.RepoRootDir, ComponentImageConfigRelPath, EnterpriseRegistryConfigKey, eRegistry); err != nil {
				return fmt.Errorf("modifying Enterprise registry config: %w", err)
			}
		}
		// Set ENTERPRISE_CRDS_DIR if specified
		if crdsDir := vc.Enterprise.Dir; crdsDir != "" {
			logrus.Warnf("Using local Enterprise CRDs from %s", crdsDir)
			env = append(env, fmt.Sprintf("ENTERPRISE_CRDS_DIR=%s", crdsDir))
		}
	}

	// Run make target to ensure files are formatted correctly and generated files are up to date.
	if out, err := command.MakeInDir(vc.RepoRootDir, strings.Join(makeTargets, " "), env...); err != nil {
		logrus.Error(out)
		return fmt.Errorf("running \"make %s\": %w", strings.Join(makeTargets, " "), err)
	}
	return nil
}

// UpdateEnterpriseConfigVersion sets all component versions and the title in the Enterprise config file to version.
func UpdateEnterpriseConfigVersion(repoRootDir, version string) error {
	if err := updateConfigVersions(repoRootDir, EnterpriseConfigPath, version); err != nil {
		return fmt.Errorf("modifying Enterprise config (%s): %w", EnterpriseConfigPath, err)
	}
	return nil
}

// UpdateCalicoConfigVersion sets all component versions and the title in the Calico config file to version.
func UpdateCalicoConfigVersion(repoRootDir, version string) error {
	if err := updateConfigVersions(repoRootDir, CalicoConfigPath, version); err != nil {
		return fmt.Errorf("modifying Calico config (%s): %w", CalicoConfigPath, err)
	}
	return nil
}

// Update the versions in the given config file located in dir to the specified version
// while preserving comments and ordering in the YAML file.
func updateConfigVersions(dir, relPath, version string) error {
	absPath := filepath.Join(dir, relPath)
	content, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", absPath, err)
	}

	// Use yaml.Node to preserve comments and order when modifying the file
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return fmt.Errorf("error parsing %s: %w", relPath, err)
	}
	var root *yaml.Node
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		root = doc.Content[0]
	} else {
		root = &doc
	}
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("unexpected YAML structure in %s: root is not a mapping", relPath)
	}
	for i := 0; i < len(root.Content); i += 2 {
		keyNode := root.Content[i]
		valNode := root.Content[i+1]

		// Update title
		if strings.EqualFold(keyNode.Value, "title") {
			valNode.Value = version
			valNode.Tag = "!!str" // ensure it is treated as a string
			continue
		}

		// Update component versions
		if strings.EqualFold(keyNode.Value, "components") && valNode.Kind == yaml.MappingNode {
			for j := 0; j < len(valNode.Content); j += 2 {
				nameNode := valNode.Content[j]
				compNode := valNode.Content[j+1] // should be a mapping node

				// Skip components that are excluded from version updates
				if excludedComponent(nameNode.Value) {
					continue
				}

				// Find "version" node and update its value
				for k := 0; k < len(compNode.Content); k += 2 {
					kNode := compNode.Content[k]
					vNode := compNode.Content[k+1]
					if strings.EqualFold(kNode.Value, "version") {
						vNode.Value = version
						vNode.Tag = "!!str"
						break
					}
				}
			}
		}
	}

	// Write updated YAML preserving node order and original comments.
	file, err := os.OpenFile(absPath, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("error opening %s for writing: %w", absPath, err)
	}
	defer func() { _ = file.Close() }()
	enc := yaml.NewEncoder(file)
	defer func() { _ = enc.Close() }()
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("error writing updated versions to %s: %w", absPath, err)
	}
	return nil
}

func excludedComponent(name string) bool {
	for _, pattern := range excludedComponentsPatterns {
		matched, err := regexp.MatchString(pattern, name)
		if err != nil {
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// UpdateCalicoComponents updates individual component versions in the Calico config file.
func UpdateCalicoComponents(repoDir string, components map[string]string) error {
	if err := updateConfigVersionsComponents(repoDir, CalicoConfigPath, components); err != nil {
		return fmt.Errorf("updating Calico components: %w", err)
	}
	return nil
}

// UpdateEnterpriseComponents updates individual component versions in the Enterprise config file.
func UpdateEnterpriseComponents(repoDir string, components map[string]string) error {
	if err := updateConfigVersionsComponents(repoDir, EnterpriseConfigPath, components); err != nil {
		return fmt.Errorf("updating Enterprise components: %w", err)
	}
	return nil
}

func updateConfigVersionsComponents(repoDir, configFile string, components map[string]string) error {
	fqPath := filepath.Join(repoDir, configFile)
	var root yaml.Node
	if data, err := os.ReadFile(fqPath); err != nil {
		return fmt.Errorf("reading local file %s: %w", configFile, err)
	} else if err = yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("unmarshalling local file %s: %w", configFile, err)
	}

	for component, version := range components {
		if err := updateComponentVersion(&root, []string{"components", component, "version"}, version); err != nil {
			return fmt.Errorf("updating component %s to %s: %w", component, version, err)
		}
	}

	// overwrite local file with updated config
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	if err := encoder.Encode(&root); err != nil {
		return fmt.Errorf("encoding updated config: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("closing encoder: %w", err)
	}
	if err := os.WriteFile(fqPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("overwriting local file %s: %w", configFile, err)
	}
	return nil
}

// updateComponentVersion traverses the yaml node to update the version of the component.
func updateComponentVersion(node *yaml.Node, path []string, version string) error {
	current := node.Content[0]
	for i, key := range path {
		found := false
		for j := 0; j < len(current.Content)-1; j += 2 {
			keyNode := current.Content[j]
			valueNode := current.Content[j+1]

			logrus.WithFields(logrus.Fields{
				"key":   keyNode.Value,
				"value": valueNode.Value,
			}).Debug("Checking key and value")

			if keyNode.Value == key {
				if i == len(path)-1 {
					valueNode.Value = version
					return nil
				}

				if valueNode.Kind == yaml.MappingNode {
					current = valueNode
					found = true
					break
				} else {
					return fmt.Errorf("expected mapping node at path %v, got %v", path[:i+1], valueNode.Kind)
				}
			}
		}

		if !found {
			return fmt.Errorf("key '%s' not found at path %v", key, path[:i+1])
		}
	}
	return nil
}

// ConfigVersions reads the current Calico and Enterprise title versions from their config files.
func ConfigVersions(repoDir string) (Versions, error) {
	versions := Versions{}
	calicoVer, err := CalicoConfigVersions(repoDir)
	if err != nil {
		return versions, fmt.Errorf("retrieving Calico version: %w", err)
	}
	versions.Calico = calicoVer.Title
	enterpriseVer, err := EnterpriseConfigVersions(repoDir)
	if err != nil {
		return versions, fmt.Errorf("retrieving Enterprise version: %w", err)
	}
	versions.Enterprise = enterpriseVer.Title
	return versions, nil
}

// CalicoConfigVersions reads the CalicoVersion from the local Calico config file.
func CalicoConfigVersions(repoDir string) (*CalicoVersion, error) {
	version, err := getConfigVersions(repoDir, CalicoConfigPath)
	if err != nil {
		return nil, fmt.Errorf("getting Calico config versions: %w", err)
	}
	return version, nil
}

// EnterpriseConfigVersions reads the CalicoVersion from the local Enterprise config file.
func EnterpriseConfigVersions(repoDir string) (*CalicoVersion, error) {
	version, err := getConfigVersions(repoDir, EnterpriseConfigPath)
	if err != nil {
		return nil, fmt.Errorf("getting Enterprise config versions: %w", err)
	}
	return version, nil
}

func getConfigVersions(repoDir, configFile string) (*CalicoVersion, error) {
	if repoDir == "" {
		return nil, fmt.Errorf("repo root dir must be specified")
	}
	if configFile == "" {
		return nil, fmt.Errorf("no config file specified")
	}
	fqPath := filepath.Join(repoDir, configFile)
	data, err := os.ReadFile(fqPath)
	if err != nil {
		return nil, fmt.Errorf("reading version file %s: %w", fqPath, err)
	}
	return ParseConfigVersions(data)
}

// GitRefConfigVersions reads Calico and Enterprise title versions from the given git ref.
func GitRefConfigVersions(gitRef string) (Versions, error) {
	v := Versions{}
	calicoVer, err := GitRefConfigCalicoVersion(gitRef)
	if err != nil {
		return v, fmt.Errorf("parsing Calico config version: %w", err)
	}
	v.Calico = calicoVer.Title
	enterpriseVer, err := GitRefConfigEnterpriseVersion(gitRef)
	if err != nil {
		return v, fmt.Errorf("parsing Enterprise config version: %w", err)
	}
	v.Enterprise = enterpriseVer.Title
	return v, nil
}

func GitRefConfigCalicoVersion(gitRef string) (*CalicoVersion, error) {
	content, err := fetchConfigVersion(CalicoConfigPath, gitRef)
	if err != nil {
		return nil, fmt.Errorf("fetching Calico config version: %w", err)
	}
	return ParseConfigVersions(content)
}

func GitRefConfigEnterpriseVersion(gitRef string) (*CalicoVersion, error) {
	content, err := fetchConfigVersion(EnterpriseConfigPath, gitRef)
	if err != nil {
		return nil, fmt.Errorf("fetching Enterprise config version: %w", err)
	}
	return ParseConfigVersions(content)
}

func ReplaceConfigVersions(rootDir, gitRef string) error {
	if err := replaceConfigVersion(rootDir, CalicoConfigPath, gitRef); err != nil {
		return fmt.Errorf("replacing Calico config version: %w", err)
	}
	if err := replaceConfigVersion(rootDir, EnterpriseConfigPath, gitRef); err != nil {
		return fmt.Errorf("replacing Enterprise config version: %w", err)
	}
	return nil
}

func fetchConfigVersion(configFile, gitRef string) ([]byte, error) {
	content, err := command.GitShowFile(gitRef, configFile)
	if err != nil {
		return nil, fmt.Errorf("git show %s in %s: %w", configFile, gitRef, err)
	}
	return []byte(content), nil
}

func replaceConfigVersion(repoDir, configFile, gitRef string) error {
	content, err := command.GitShowFile(gitRef, configFile)
	if err != nil {
		return fmt.Errorf("git show %s in %s: %w", configFile, gitRef, err)
	}
	fqPath := filepath.Join(repoDir, configFile)
	if err := os.WriteFile(fqPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing to %s file from %s: %w", fqPath, gitRef, err)
	}
	return nil
}
