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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
		apiComponentName,
		calicoComponentName,
		networkingCalicoComponentName,
	}

	// Components to ignore when generating the operator components file.
	operatorIgnoreComponents = []string{
		flannelComponentName,
		testSignerComponentName,
		flannelMigrationController,
	}
)

var FlannelComponent = registry.Component{
	Registry: "quay.io",
	Image:    "coreos/flannel",
	Version:  "v0.12.0",
}

var (
	// Map of component names to their image names.
	componentToImageMap = map[string]string{
		"calicoctl":                 "ctl",
		"flexvol":                   "pod2daemon-flexvol",
		"csi-node-driver-registrar": "node-driver-registrar",
	}
	// Map of image names to their component names.
	// It is initialized lazily and should be accessed via mapImageToComponent.
	imageToComponentMap = map[string]string{}
)

const (
	pinnedVersionFileName      = "pinned_versions.yml"
	operatorComponentsFileName = "pinned_components.yml"
)

const (
	apiComponentName              = "api"
	calicoComponentName           = "calico"
	flannelComponentName          = "flannel"
	networkingCalicoComponentName = "networking-calico"
	testSignerComponentName       = "test-signer"
	flannelMigrationController    = "flannel-migration-controller"
)

var once sync.Once

type PinnedVersions[T version.Versions] interface {
	GenerateFile() (T, error)
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
//
// Images returned from this function are expected to eventually be in the format "<registry>/<image-name>"
// e.g. "quay.io/calico/node" where <registry> is "quay.io/calico" and <image-name> is "node".
// NOTE: this only sets the image name portion (i.e. "node"), the registry is set elsewhere.
func (p *PinnedVersion) ImageComponents(includeOperator bool) map[string]registry.Component {
	components := make(map[string]registry.Component)
	for name, component := range p.Components {
		// Remove components that should be excluded. Either because they do not have an image, or not built by Calico.
		if slices.Contains(noImageComponents, name) {
			continue
		}
		if img, found := componentToImageMap[name]; found {
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

	releaseName   string
	productBranch string
	versionData   *version.HashreleaseVersions
}

// GenerateFile generates the pinned version file.
func (p *CalicoPinnedVersions) GenerateFile() (*version.HashreleaseVersions, error) {
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)

	productBranch, err := utils.GitBranch(p.RootDir)
	if err != nil {
		return nil, fmt.Errorf("cannot get current branch: %w", err)
	}
	p.productBranch = productBranch
	productVer, err := command.GitVersion(p.RootDir, true)
	if err != nil {
		return nil, fmt.Errorf("failed to determine product version: %w", err)
	}
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), version.DeterminePublishStream(productBranch, productVer), RandomWord())
	p.releaseName = strings.ReplaceAll(releaseName, ".", "-")
	operatorVer, err := p.OperatorCfg.GitVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to determine operator version: %w", err)
	}
	p.versionData = version.NewHashreleaseVersions(version.New(productVer), operatorVer)
	if err := generatePinnedVersionFile(p); err != nil {
		return nil, err
	}

	if p.BaseHashreleaseDir != "" {
		hashreleaseDir := filepath.Join(p.BaseHashreleaseDir, p.versionData.Hash())
		if err := os.MkdirAll(hashreleaseDir, utils.DirPerms); err != nil {
			return nil, err
		}
		if err := utils.CopyFile(pinnedVersionPath, filepath.Join(hashreleaseDir, pinnedVersionFileName)); err != nil {
			return nil, err
		}
	}

	return p.versionData, nil
}

func mapImageToComponent(imageName, version string) (string, registry.Component) {
	once.Do(func() {
		// Initialize the image to component map.
		for c, img := range componentToImageMap {
			imageToComponentMap[img] = c
		}
	})
	if compName, found := imageToComponentMap[imageName]; found {
		return compName, registry.Component{
			Version: version,
			Image:   imageName,
		}
	}
	return imageName, registry.Component{Version: version}
}

func generatePinnedVersionFile(p *CalicoPinnedVersions) error {
	pinnedVersionPath := PinnedVersionFilePath(p.Dir)
	components := map[string]registry.Component{
		apiComponentName: {
			Version: p.versionData.ProductVersion(),
		},
		calicoComponentName: {
			Version: p.versionData.ProductVersion(),
		},
		networkingCalicoComponentName: {
			Version: p.versionData.ReleaseBranch(p.ReleaseBranchPrefix),
		},
		flannelComponentName: FlannelComponent,
	}
	for _, img := range utils.ReleaseImages() {
		name, c := mapImageToComponent(img, p.versionData.ProductVersion())
		components[name] = c
	}
	pinned := PinnedVersion{
		Title:       p.versionData.ProductVersion(),
		ManifestURL: fmt.Sprintf("https://%s.%s", p.releaseName, hashreleaseserver.BaseDomain),
		ReleaseName: p.releaseName,
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			p.releaseName, time.Now().Format(time.RFC1123), p.productBranch, p.OperatorCfg.Branch),
		Hash: p.versionData.Hash(),
		TigeraOperator: registry.Component{
			Image:    p.OperatorCfg.Image,
			Registry: p.OperatorCfg.Registry,
			Version:  p.versionData.OperatorVersion(),
		},
		Components: components,
	}

	logrus.WithField("file", pinnedVersionPath).Info("Creating pinned version file")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return fmt.Errorf("cannot create pinned version file: %w", err)
	}
	defer func() { _ = pinnedVersionFile.Close() }()
	enc := yaml.NewEncoder(pinnedVersionFile)
	enc.SetIndent(2)
	defer func() { _ = enc.Close() }()

	if err := enc.Encode([]PinnedVersion{pinned}); err != nil {
		return fmt.Errorf("failed to encode pinned version file: %w", err)
	}
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
