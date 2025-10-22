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
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

var (
	// Components that do not produce images.
	noImageComponents = []string{
		"calico",
		"api",
		"networking-calico",
	}

	// Components to ignore when generating the operator components file.
	operatorIgnoreComponents = []string{
		flannelComponentName,
		"test-signer",
	}
)

//go:embed templates/calico-versions.yaml.gotmpl
var calicoTemplate string

const (
	pinnedVersionFileName      = "pinned_versions.yml"
	operatorComponentsFileName = "pinned_components.yml"
)

const (
	flannelComponentName = "flannel"
)

type PinnedVersions interface {
	GenerateFile() (version.Versions, error)
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
	ManifestURL    string                        `yaml:"manifest_url,omitempty"`
	ReleaseName    string                        `yaml:"release_name,omitempty"`
	Note           string                        `yaml:"note,omitempty"`
	Hash           string                        `yaml:"full_hash,omitempty"`
	TigeraOperator registry.Component            `yaml:"tigera-operator"`
	Components     map[string]registry.Component `yaml:"components"`
}

// operatorComponents returns a map of the Tigera operator and its init image components.
func (p *PinnedVersion) operatorComponents() map[string]registry.Component {
	op := registry.OperatorComponent{Component: p.TigeraOperator}
	opInit := op.InitImage()
	return map[string]registry.Component{
		op.Image:     op.Component,
		opInit.Image: opInit,
	}
}

// ImageComponents returns a map of all components that produce images
// including Tigera operator and its init image if includeOperator is true.
func (p *PinnedVersion) ImageComponents(includeOperator bool) map[string]registry.Component {
	components := make(map[string]registry.Component)
	for name, component := range p.Components {
		// Remove components that should be excluded. Either because they do not have an image, or not built by Calico.
		if slices.Contains(noImageComponents, name) {
			continue
		}
		if img := registry.ImageMap[name]; img != "" {
			component.Image = img
		} else if component.Image == "" {
			component.Image = name
		}
		components[name] = component
	}

	if includeOperator {
		for name, component := range p.operatorComponents() {
			components[name] = component
		}
	}
	return components
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
	if d.ReleaseName == "" || d.BaseDomain == "" {
		return ""
	}
	return fmt.Sprintf("https://%s.%s", d.ReleaseName, d.BaseDomain)
}

// PinnedVersionFilePath returns the path of the pinned version file.
func PinnedVersionFilePath(outputDir string) string {
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
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)

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
	if err := generatePinnedVersionFile(tmplData, p.Dir); err != nil {
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

func generatePinnedVersionFile(data *calicoTemplateData, outputDir string) error {
	tmpl, err := template.New("pinnedversion").Parse(calicoTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	pinnedVersionPath := PinnedVersionFilePath(outputDir)
	logrus.WithField("file", pinnedVersionPath).Info("Creating pinned version file")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return fmt.Errorf("failed to create pinned version file: %w", err)
	}
	defer func() { _ = pinnedVersionFile.Close() }()
	if err := tmpl.Execute(pinnedVersionFile, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}
	logrus.WithField("file", pinnedVersionPath).Info("Pinned version file generated successfully")
	return nil
}

// GenerateOperatorComponents generates the components-version.yaml for operator.
// It also copies the generated file to the output directory if provided.
func GenerateOperatorComponents(srcDir, outputDir string) (registry.OperatorComponent, string, error) {
	op := registry.OperatorComponent{}
	pinnedVersion, err := retrievePinnedVersion(srcDir)
	if err != nil {
		return op, "", err
	}

	// Remove components that are not needed in the operator components file.
	// These either do not produce images or are not used by the operator.
	for _, c := range operatorIgnoreComponents {
		delete(pinnedVersion.Components, c)
	}

	logrus.Info("Generating operator components file")
	operatorComponentsFilePath := filepath.Join(srcDir, operatorComponentsFileName)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return op, "", err
	}
	defer func() { _ = operatorComponentsFile.Close() }()

	enc := yaml.NewEncoder(operatorComponentsFile)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()

	if err := enc.Encode(pinnedVersion); err != nil {
		return op, "", err
	}
	if outputDir != "" {
		if err := utils.CopyFile(operatorComponentsFilePath, filepath.Join(outputDir, operatorComponentsFileName)); err != nil {
			return op, "", err
		}
	}
	op.Component = pinnedVersion.TigeraOperator
	logrus.WithField("file", operatorComponentsFilePath).Info("Operator components file generated successfully")
	return op, operatorComponentsFilePath, nil
}

// retrievePinnedVersion retrieves the pinned version from the pinned version file.
func retrievePinnedVersion(outputDir string) (PinnedVersion, error) {
	pinnedVersionPath := PinnedVersionFilePath(outputDir)
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

// RetrieveImageComponents retrieves the images from Calico components in the pinned version file that produce images.
// It also adds the Tigera operator and its init image to the returned map.
//
// Images returned from this function are expected to be in the format "<registry>/<image-name>" where <registry> includes the registry and image path.
// However, the versions.yml file represents images differently, including the image path as the first part of the image name instead of as part of the registry.
// As a result, the image path is stripped from the image name to only return the image name so that images are properly formatted.
//
// For example, if the image name is "calico/node", this allows the fully qualified image to be "quay.io/calico/node" when a registry of `quay.io/calico` is prepended.
// and prevents duplication of the image path(i.e. "quay.io/calico/calico/node").
func RetrieveImageComponents(outputDir string) (map[string]registry.Component, error) {
	pinnedVersion, err := retrievePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}
	return pinnedVersion.ImageComponents(true), nil
}

func RetrieveVersions(outputDir string) (version.Versions, error) {
	pinnedVersion, err := retrievePinnedVersion(outputDir)
	if err != nil {
		return nil, err
	}

	return version.NewHashreleaseVersions(version.New(pinnedVersion.Title), pinnedVersion.TigeraOperator.Version), nil
}
