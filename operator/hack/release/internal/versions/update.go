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
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectcalico/calico/operator/hack/release/internal/command"
)

const (
	configDir = "config"
	// EnterpriseConfigPath is the repo-relative path to the Enterprise versions config file.
	EnterpriseConfigPath = configDir + "/enterprise_versions.yml"
)

// Versions holds the release version strings read from the version config files.
type Versions struct {
	Enterprise string
}

// ToMap returns a human-readable map of non-empty version strings keyed by product name.
func (v Versions) ToMap() map[string]string {
	result := make(map[string]string)
	if v.Enterprise != "" {
		result["Calico Enterprise"] = v.Enterprise
	}
	return result
}

// ConfigVersions reads the current title versions from the config files.
func ConfigVersions(repoDir string) (Versions, error) {
	versions := Versions{}
	enterpriseVer, err := EnterpriseConfigVersions(repoDir)
	if err != nil {
		return versions, fmt.Errorf("retrieving Enterprise version: %w", err)
	}
	versions.Enterprise = enterpriseVer.Title
	return versions, nil
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

// GitRefConfigVersions reads title versions from the given git ref.
func GitRefConfigVersions(gitRef string) (Versions, error) {
	v := Versions{}
	enterpriseVer, err := GitRefConfigEnterpriseVersion(gitRef)
	if err != nil {
		return v, fmt.Errorf("parsing Enterprise config version: %w", err)
	}
	v.Enterprise = enterpriseVer.Title
	return v, nil
}

func GitRefConfigEnterpriseVersion(gitRef string) (*CalicoVersion, error) {
	content, err := fetchConfigVersion(EnterpriseConfigPath, gitRef)
	if err != nil {
		return nil, fmt.Errorf("fetching Enterprise config version: %w", err)
	}
	return ParseConfigVersions(content)
}

func ReplaceConfigVersions(rootDir, gitRef string) error {
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
