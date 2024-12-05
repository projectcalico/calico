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

	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/command"
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

type OperatorConfig struct {
	Dir      string
	Branch   string
	Image    string
	Registry string
}

func (c *OperatorConfig) GitVersion() (version.Version, error) {
	previousTag, err := command.GitVersion(c.Dir, true)
	if err != nil {
		logrus.WithError(err).Error("failed to determine operator git version")
		return version.Version(""), err
	}
	logrus.WithField("out", previousTag).Info("Current git describe")
	return version.New(previousTag), nil
}

func (c *OperatorConfig) GitBranch() (string, error) {
	return command.GitInDir(c.Dir, "rev-parse", "--abbrev-ref", "HEAD")
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

func (d *PinnedVersionData) ReleaseURL() string {
	return fmt.Sprintf("https://%s.%s", d.ReleaseName, d.BaseDomain)
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

func (p *PinnedVersion) ProductVersion() string {
	return p.Components[utils.Calico].Version
}

func (p *PinnedVersion) HelmChartVersion() string {
	return p.ProductVersion()
}

func (p *PinnedVersion) Operator() registry.OperatorComponent {
	return registry.OperatorComponent{
		Component: p.TigeraOperator,
	}
}

// PinnedVersionFile represents the pinned version file.
type PinnedVersionFile []PinnedVersion

func pinnedVersionFilePath(outputDir string) string {
	return filepath.Join(outputDir, pinnedVersionFileName)
}

func operatorComponentsFilePath(outputDir string) string {
	return filepath.Join(outputDir, operatorComponentsFileName)
}

type PinnedVersions interface {
	Get() (PinnedVersion, error)
	Generate() (string, map[string]any, error)
	OperatorComponent() (registry.OperatorComponent, string, error)
	ComponentsToValidate() (map[string]registry.Component, error)
	LoadHashrelease(hashreleaseBaseDir string) (*hashreleaseserver.Hashrelease, error)
}

func New(cfg map[string]any, outputDir string) PinnedVersions {
	return &CalicoPinnedVersions{
		Cfg:       cfg,
		OutputDir: outputDir,
	}
}

type CalicoPinnedVersions struct {
	Cfg       map[string]any
	OutputDir string
}

func (p *CalicoPinnedVersions) RepoRootDir() string {
	return p.Cfg["repoRootDir"].(string)
}

func (p *CalicoPinnedVersions) ReleaseBranchPrefix() string {
	return p.Cfg["releaseBranchPrefix"].(string)
}

func (p *CalicoPinnedVersions) OperatorConfig() OperatorConfig {
	return p.Cfg["operator"].(OperatorConfig)
}

func (p *CalicoPinnedVersions) Get() (PinnedVersion, error) {
	pinnedVersionPath := pinnedVersionFilePath(p.OutputDir)
	var pinnedVersionFile PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return PinnedVersion{}, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return PinnedVersion{}, err
	}
	return pinnedVersionFile[0], nil
}

func (p *CalicoPinnedVersions) Generate() (string, map[string]any, error) {
	pinnedVersionPath := pinnedVersionFilePath(p.OutputDir)

	productBranch, err := utils.GitBranch(p.RepoRootDir())
	if err != nil {
		return "", nil, err
	}

	productVersion := version.GitVersion()
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, string(productVersion)), RandomWord())
	releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorCfg := p.OperatorConfig()
	operatorBranch, err := operatorCfg.GitBranch()
	if err != nil {
		return "", nil, err
	}
	operatorVersion, err := operatorCfg.GitVersion()
	if err != nil {
		return "", nil, err
	}
	pinnedOperatorVersion := operatorVersion.FormattedString() + "-" + releaseName
	tmpl, err := template.New("pinnedversion").Parse(calicoVersionTemplateData)
	if err != nil {
		return "", nil, err
	}
	data := &PinnedVersionData{
		ReleaseName:    releaseName,
		BaseDomain:     hashreleaseserver.BaseDomain,
		ProductVersion: productVersion.FormattedString(),
		Operator: registry.Component{
			Version:  pinnedOperatorVersion,
			Image:    operatorCfg.Image,
			Registry: operatorCfg.Registry,
		},
		Hash: productVersion.FormattedString() + "-" + operatorVersion.FormattedString(),
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			releaseName, time.Now().Format(time.RFC1123), productBranch, operatorBranch),
		ReleaseBranch: productVersion.ReleaseBranch(p.ReleaseBranchPrefix()),
	}
	logrus.WithField("file", pinnedVersionPath).Info("Generating pinned-version.yaml")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		logrus.WithError(err).Error("Failed to create pinned-version.yaml file")
		return "", nil, err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, data); err != nil {
		logrus.WithError(err).Error("Failed to generate pinned-version.yaml from template")
		return "", nil, err
	}

	var versions map[string]any
	if err := mapstructure.Decode(version.Data{
		ProductVersion:  productVersion,
		OperatorVersion: version.New(pinnedOperatorVersion),
	}, &versions); err != nil {
		return "", nil, err
	}

	releaseMetadata := map[string]any{
		"versions": versions,
		"hash":     data.Hash,
	}

	return pinnedVersionPath, releaseMetadata, nil
}

func (p *CalicoPinnedVersions) OperatorComponent() (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersionPath := pinnedVersionFilePath(p.OutputDir)
	logrus.WithField("file", pinnedVersionPath).Info("Generating components-version.yaml for operator")
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return op, "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return op, "", err
	}
	operatorComponentsFilePath := operatorComponentsFilePath(p.OutputDir)
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

func (p *CalicoPinnedVersions) LoadHashrelease(hashreleaseBaseDir string) (*hashreleaseserver.Hashrelease, error) {
	pinnedVersion, err := p.Get()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version")
		return nil, err
	}
	var versions map[string]any
	if err := mapstructure.Decode(version.Data{
		ProductVersion:  version.New(pinnedVersion.ProductVersion()),
		OperatorVersion: version.New(pinnedVersion.Operator().Version),
	}, versions); err != nil {
		return nil, err
	}
	return &hashreleaseserver.Hashrelease{
		Name:     pinnedVersion.ReleaseName,
		Hash:     pinnedVersion.Hash,
		Note:     pinnedVersion.Note,
		Versions: versions,
		Source:   filepath.Join(hashreleaseBaseDir, pinnedVersion.Title),
		Time:     time.Now(),
	}, nil
}

func (p *CalicoPinnedVersions) ComponentsToValidate() (map[string]registry.Component, error) {
	pinnedVersionPath := pinnedVersionFilePath(p.OutputDir)
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
