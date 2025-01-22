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

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
	"github.com/projectcalico/calico/release/pkg/manager/calico"
)

//go:embed templates/calico-versions.yaml.gotmpl
var calicoTemplate string

const (
	pinnedVersionFileName      = "pinned_version.yml"
	operatorComponentsFileName = "pinned_components.yml"
)

var noImageComponents = []string{
	utils.Calico,
	"calico/api",
	"networking-calico",
}

type PinnedVersions interface {
	GenerateFile() (version.Versions, error)
	ManagerOptions() ([]calico.Option, error)
}

type OperatorConfig struct {
	Dir      string
	Branch   string
	Registry string
	Image    string // i.e tigera/operator
}

func (c OperatorConfig) GitVersion() (string, error) {
	tag, err := command.GitVersion(c.Dir, true)
	if err != nil {
		logrus.WithError(err).Error("Failed to determine operator git version")
		return "", err
	}
	logrus.WithField("out", tag).Info("Current git describe")
	return tag, nil
}

func (c OperatorConfig) GitBranch() (string, error) {
	return command.GitInDir(c.Dir, "rev-parse", "--abbrev-ref", "HEAD")
}

// PinnedVersion represents an entry in pinned version file.
type PinnedVersion struct {
	Title          string                        `yaml:"title"`
	ManifestURL    string                        `yaml:"manifest_url"`
	ReleaseName    string                        `yaml:"release_name,omitempty"`
	Note           string                        `yaml:"note"`
	Hash           string                        `yaml:"full_hash"`
	TigeraOperator registry.Component            `yaml:"tigera-operator"`
	Components     map[string]registry.Component `yaml:"components"`
}

// calicoTemplateData is used to generate the pinned version file from the template.
type calicoTemplateData struct {
	ReleaseName    string
	BaseDomain     string
	ProductVersion string
	Operator       registry.Component
	Note           string
	Hash           string
	ReleaseBranch  string
}

func (d *calicoTemplateData) ReleaseURL() string {
	return fmt.Sprintf("https://%s.%s", d.ReleaseName, d.BaseDomain)
}

func pinnedVersionFilePath(outputDir string) string {
	return filepath.Join(outputDir, pinnedVersionFileName)
}

// CalicoPinnedVersions is the implementation of PinnedVersions for Calico.
// It generates the pinned version file for Calico
// and provides the manager options for the Calico manager.
type CalicoPinnedVersions struct {
	// RootDir is the root directory of the repository.
	RootDir string

	// Dir is the directory to store the pinned version file.
	Dir string

	// BaseHashreleaseDir is the release artifacts directory to also store the generated file.
	BaseHashreleaseDir string

	// ReleaseBranchPrefix is the prefix for the release branch.
	ReleaseBranchPrefix string

	// OperatorCfg is the configuration for the operator.
	OperatorCfg OperatorConfig
}

// GenerateFile generates the pinned version file.
func (p *CalicoPinnedVersions) GenerateFile() (version.Versions, error) {
	pinnedVersionPath := pinnedVersionFilePath(p.Dir)

	productBranch, err := utils.GitBranch(p.RootDir)
	if err != nil {
		return nil, err
	}
	productVer, err := command.GitVersion(p.RootDir, true)
	if err != nil {
		logrus.WithError(err).Error("Failed to determine product git version")
		return nil, err
	}
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, productVer), RandomWord())
	releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorBranch, err := p.OperatorCfg.GitBranch()
	if err != nil {
		return nil, err
	}
	operatorVer, err := p.OperatorCfg.GitVersion()
	if err != nil {
		return nil, err
	}
	versionData := version.NewHashreleaseVersions(version.New(productVer), operatorVer)
	tmpl, err := template.New("pinnedversion").Parse(calicoTemplate)
	if err != nil {
		return nil, err
	}
	tmplData := &calicoTemplateData{
		ReleaseName:    releaseName,
		BaseDomain:     hashreleaseserver.BaseDomain,
		ProductVersion: versionData.ProductVersion(),
		Operator: registry.Component{
			Version:  versionData.OperatorVersion(),
			Image:    p.OperatorCfg.Image,
			Registry: p.OperatorCfg.Registry,
		},
		Hash: versionData.Hash(),
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			releaseName, time.Now().Format(time.RFC1123), productBranch, operatorBranch),
		ReleaseBranch: versionData.ReleaseBranch(p.ReleaseBranchPrefix),
	}
	logrus.WithField("file", pinnedVersionPath).Info("Generating pinned version file")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return nil, err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, tmplData); err != nil {
		return nil, err
	}

	if p.BaseHashreleaseDir != "" {
		hashreleaseDir := filepath.Join(p.BaseHashreleaseDir, versionData.Hash())
		if err := os.MkdirAll(hashreleaseDir, utils.DirPerms); err != nil {
			return nil, err
		}
		if err := utils.CopyFile(pinnedVersionPath, filepath.Join(hashreleaseDir, pinnedVersionFileName)); err != nil {
			return nil, err
		}
	}

	return versionData, nil
}

// ManagerOptions returns the options for the manager.
func (p *CalicoPinnedVersions) ManagerOptions() ([]calico.Option, error) {
	pinnedVersion, err := retrievePinnedVersion(p.Dir)
	if err != nil {
		return nil, err
	}

	return []calico.Option{
		calico.WithVersion(pinnedVersion.Title),
		calico.WithOperatorVersion(pinnedVersion.TigeraOperator.Version),
	}, nil
}

// GenerateOperatorComponents generates the components-version.yaml for operator.
// It also copies the generated file to the output directory if provided.
func GenerateOperatorComponents(srcDir, outputDir string) (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersion, err := retrievePinnedVersion(srcDir)
	if err != nil {
		return op, "", err
	}
	operatorComponentsFilePath := filepath.Join(srcDir, operatorComponentsFileName)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return op, "", err
	}
	defer operatorComponentsFile.Close()
	if err = yaml.NewEncoder(operatorComponentsFile).Encode(pinnedVersion); err != nil {
		return op, "", err
	}
	if outputDir != "" {
		if err := utils.CopyFile(operatorComponentsFilePath, filepath.Join(outputDir, operatorComponentsFileName)); err != nil {
			return op, "", err
		}
	}
	op.Component = pinnedVersion.TigeraOperator
	return op, operatorComponentsFilePath, nil
}

// retrievePinnedVersion retrieves the pinned version from the pinned version file.
func retrievePinnedVersion(outputDir string) (PinnedVersion, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedVersionFile []PinnedVersion
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return PinnedVersion{}, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return PinnedVersion{}, err
	}
	return pinnedVersionFile[0], nil
}

// RetrievePinnedOperatorVersion retrieves the operator version from the pinned version file.
func RetrievePinnedOperator(outputDir string) (registry.OperatorComponent, error) {
	pinnedVersion, err := retrievePinnedVersion(outputDir)
	if err != nil {
		return registry.OperatorComponent{}, err
	}
	return registry.OperatorComponent{
		Component: pinnedVersion.TigeraOperator,
	}, nil
}

// LoadHashrelease loads the hashrelease from the pinned version file.
func LoadHashrelease(repoRootDir, outputDir, hashreleaseSrcBaseDir string, latest bool) (*hashreleaseserver.Hashrelease, error) {
	productBranch, err := utils.GitBranch(repoRootDir)
	if err != nil {
		logrus.WithError(err).Error("Failed to get current branch")
		return nil, err
	}
	pinnedVersion, err := retrievePinnedVersion(outputDir)
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
		Source:          filepath.Join(hashreleaseSrcBaseDir, pinnedVersion.Hash),
		Time:            time.Now(),
		Latest:          latest,
	}, nil
}

func RetrieveImageComponents(outputDir string) (map[string]registry.Component, error) {
	pinnedVersion, err := retrievePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}
	components := pinnedVersion.Components
	operator := registry.OperatorComponent{Component: pinnedVersion.TigeraOperator}
	components[operator.Image] = operator.Component
	initImage := operator.InitImage()
	components[initImage.Image] = operator.InitImage()
	for name, component := range components {
		// Remove components that do not produce images.
		if utils.Contains(noImageComponents, name) {
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

func RetrieveVersions(outputDir string) (version.Versions, error) {
	pinnedVersion, err := retrievePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}

	return version.NewHashreleaseVersions(version.New(pinnedVersion.Title), pinnedVersion.TigeraOperator.Version), nil
}
