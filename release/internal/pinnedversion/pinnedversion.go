// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package pinnedversion

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

//go:embed templates/calico-version.yaml.gotmpl
var calicoVersionTemplateData string

const (
	pinnedVersionFileName      = "pinned-version.yaml"
	operatorComponentsFileName = "components.yaml"
)

// Config represents the configuration needed to generate the pinned version file.
type Config struct {
	// RootDir is the root directory of the repository.
	RootDir string

	// ReleaseBranchPrefix is the prefix for the release branch.
	ReleaseBranchPrefix string

	// Operator is the configuration for the operator.
	Operator config.OperatorConfig
}

// PinnedVersionData represents the data needed to generate the pinned version file from the template.
type PinnedVersionData struct {
	// ReleaseName is the name of the release.
	ReleaseName string

	// BaseDomain is the base domain for the docs site.
	BaseDomain string

	// ProductVersion is the version of the product.
	ProductVersion string

	// Operator is the operator component.
	Operator registry.Component

	// Note is the note for the release.
	Note string

	// Hash is the hash of the release.
	Hash string

	// ReleaseBranch is the release branch of the release.
	ReleaseBranch string
}

// PinnedVersion represents an entry in pinned version file.
type PinnedVersion struct {
	Title          string                        `yaml:"title"`
	ManifestURL    string                        `yaml:"manifest_url"`
	ReleaseName    string                        `yaml:"release_name"`
	Note           string                        `yaml:"note"`
	Hash           string                        `yaml:"full_hash"`
	TigeraOperator registry.Component            `yaml:"tigera-operator"`
	Components     map[string]registry.Component `yaml:"components"`
}

// PinnedVersionFile represents the pinned version file.
type PinnedVersionFile []PinnedVersion

func pinnedVersionFilePath(outputDir string) string {
	return filepath.Join(outputDir, pinnedVersionFileName)
}

func operatorComponentsFilePath(outputDir string) string {
	return filepath.Join(outputDir, operatorComponentsFileName)
}

// GeneratePinnedVersionFile generates the pinned version file.
func GeneratePinnedVersionFile(cfg Config, outputDir string) (string, *PinnedVersionData, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)

	productBranch, err := utils.GitBranch(cfg.RootDir)
	if err != nil {
		return "", nil, err
	}

	productVersion := version.GitVersion()
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, string(productVersion)), RandomWord())
	releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorBranch, err := cfg.Operator.GitBranch()
	if err != nil {
		return "", nil, err
	}
	operatorVersion := cfg.Operator.GitVersion()
	tmpl, err := template.New("pinnedversion").Parse(calicoVersionTemplateData)
	if err != nil {
		return "", nil, err
	}
	data := &PinnedVersionData{
		ReleaseName:    releaseName,
		BaseDomain:     hashreleaseserver.BaseDomain,
		ProductVersion: productVersion.FormattedString(),
		Operator: registry.Component{
			Version:  operatorVersion.FormattedString() + "-" + releaseName,
			Image:    cfg.Operator.Image,
			Registry: cfg.Operator.Registry,
		},
		Hash: productVersion.FormattedString() + "-" + operatorVersion.FormattedString(),
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			releaseName, time.Now().Format(time.RFC1123), productBranch, operatorBranch),
		ReleaseBranch: productVersion.ReleaseBranch(cfg.ReleaseBranchPrefix),
	}
	logrus.WithField("file", pinnedVersionPath).Info("Generating pinned-version.yaml")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return "", nil, err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, data); err != nil {
		return "", nil, err
	}

	return pinnedVersionPath, data, nil
}

// GenerateOperatorComponents generates the components-version.yaml for operator.
func GenerateOperatorComponents(outputDir string) (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	logrus.WithField("file", pinnedVersionPath).Info("Generating components-version.yaml for operator")
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return op, "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return op, "", err
	}
	operatorComponentsFilePath := operatorComponentsFilePath(outputDir)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return op, "", err
	}
	defer operatorComponentsFile.Close()
	if err = yaml.NewEncoder(operatorComponentsFile).Encode(pinnedversion[0]); err != nil {
		return op, "", err
	}
	op.Component = pinnedversion[0].TigeraOperator
	return op, operatorComponentsFilePath, nil
}

// RetrievePinnedVersion retrieves the pinned version from the pinned version file.
func RetrievePinnedVersion(outputDir string) (PinnedVersion, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedVersionFile PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return PinnedVersion{}, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return PinnedVersion{}, err
	}
	return pinnedVersionFile[0], nil
}

// RetrievePinnedOperatorVersion retrieves the operator version from the pinned version file.
func RetrievePinnedOperator(outputDir string) (registry.OperatorComponent, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedVersionFile PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return registry.OperatorComponent{}, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return registry.OperatorComponent{}, err
	}
	return registry.OperatorComponent{
		Component: pinnedVersionFile[0].TigeraOperator,
	}, nil
}

// RetrieveComponentsToValidate retrieves the components to validate from the pinned version file.
func RetrieveComponentsToValidate(outputDir string) (map[string]registry.Component, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return nil, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return nil, err
	}
	components := pinnedversion[0].Components
	operator := registry.OperatorComponent{Component: pinnedversion[0].TigeraOperator}
	components[operator.Image] = operator.Component
	initImage := operator.InitImage()
	components[initImage.Image] = operator.InitImage()
	for name, component := range components {
		// Skip components that do not produce images.
		if name == "calico" || name == "calico/api" || name == "networking-calico" {
			delete(components, name)
			continue
		}
		img := registry.ImageMap[name]
		if img != "" {
			component.Image = img
		} else if component.Image == "" {
			component.Image = name
		}
		components[name] = component
	}
	return components, nil
}

func LoadHashrelease(repoRootDir, tmpDir, srcDir string) (*hashreleaseserver.Hashrelease, error) {
	productBranch, err := utils.GitBranch(repoRootDir)
	if err != nil {
		logrus.WithError(err).Errorf("Failed to get %s branch name", utils.ProductName)
		return nil, err
	}
	pinnedVersion, err := RetrievePinnedVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version")
	}
	return &hashreleaseserver.Hashrelease{
		Name:            pinnedVersion.ReleaseName,
		Hash:            pinnedVersion.Hash,
		Note:            pinnedVersion.Note,
		Stream:          version.DeterminePublishStream(productBranch, pinnedVersion.Title),
		ProductVersion:  pinnedVersion.Title,
		OperatorVersion: pinnedVersion.TigeraOperator.Version,
		Source:          srcDir,
		Time:            time.Now(),
	}, nil
}
