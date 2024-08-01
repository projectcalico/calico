package hashrelease

import (
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

//go:embed templates/pinned-version.yaml.gotmpl
var pinnedVersionTemplateData string

const (
	pinnedVersionFileName      = "pinned-version.yaml"
	operatorComponentsFileName = "components.yaml"
)

// Component represents a component in the pinned version file.
type Component struct {
	Version  string `yaml:"version"`
	Image    string `yaml:"image,omitempty"`
	Registry string `yaml:"registry,omitempty"`
}

// ImageRef returns the image reference of the component.
func (c Component) ImageRef() registry.ImageRef {
	return registry.ParseImage(c.String())
}

// String returns the string representation of the component.
// The string representation is in the format of registry/image:version.
func (c Component) String() string {
	registry := registry.GetRegistry(c.Registry)
	return fmt.Sprintf("%s/%s:%s", registry.URL(), c.Image, c.Version)
}

// PinnedVersionData represents the data needed to generate the pinned version file.
type PinnedVersionData struct {
	ReleaseName   string
	CalicoVersion string
	Operator      Component
	Note          string
	Hash          string
	Registry      string
	ReleaseBranch string
}

// PinnedVersion represents an entry in pinned version file.
type PinnedVersion struct {
	Title          string               `yaml:"title"`
	ManifestURL    string               `yaml:"manifest_url"`
	ReleaseName    string               `yaml:"release_name"`
	Note           string               `yaml:"note"`
	Hash           string               `yaml:"full_hash"`
	TigeraOperator Component            `yaml:"tigera-operator"`
	Components     map[string]Component `yaml:"components"`
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
func GeneratePinnedVersionFile(rootDir, operatorDir, devTagSuffix, registry, outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	if _, err := os.Stat(pinnedVersionPath); err == nil {
		logrus.WithField("file", pinnedVersionPath).Info("Pinned version file already exists")
		return pinnedVersionPath, fmt.Errorf("pinned version file already exists")
	}
	calicoBranch, err := utils.GitBranch(rootDir)
	if err != nil {
		return "", err
	}
	// TODO: Validate this is a acceptable branch i.e. master or release-vX.Y
	releaseName := fmt.Sprintf("%s-%s-%s", time.Now().Format("2006-01-02"), calicoBranch, RandomWord())
	calicoVersion, err := utils.GitVersion(rootDir)
	if err != nil {
		return "", err
	}
	if !version.IsDevVersion(calicoVersion, devTagSuffix) {
		return "", fmt.Errorf("calico version %s does not have dev tag %s", calicoVersion, devTagSuffix)
	}
	operatorBranch, err := operator.GitBranch(operatorDir)
	if err != nil {
		return "", err
	}
	operatorVersion, err := operator.GitVersion(operatorDir)
	if err != nil {
		return "", err
	}
	if !version.IsDevVersion(operatorVersion, devTagSuffix) {
		return "", fmt.Errorf("operator version %s does not have dev tag %s", operatorVersion, devTagSuffix)
	}
	tmpl, err := template.New("pinnedversion").Parse(pinnedVersionTemplateData)
	if err != nil {
		return "", err
	}
	data := &PinnedVersionData{
		ReleaseName:   releaseName,
		CalicoVersion: calicoVersion,
		Operator: Component{
			Version:  operatorVersion + "-" + releaseName,
			Image:    operator.ImageName,
			Registry: operator.Registry,
		},
		Hash: calicoVersion + "-" + operatorVersion,
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			releaseName, time.Now().Format(time.RFC1123), calicoBranch, operatorBranch),
		ReleaseBranch: calicoBranch,
	}
	if registry != "" {
		data.Operator.Registry = registry
		data.Registry = registry
	}
	logrus.WithField("file", pinnedVersionPath).Info("Generating pinned-version.yaml")
	pinnedVersionFile, err := os.Create(pinnedVersionPath)
	if err != nil {
		return "", err
	}
	defer pinnedVersionFile.Close()
	if err := tmpl.Execute(pinnedVersionFile, data); err != nil {
		return "", err
	}

	return pinnedVersionPath, nil
}

// GenerateComponentsVersionFile generates the components-version.yaml for operator.
func GenerateComponentsVersionFile(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	logrus.WithField("file", pinnedVersionPath).Info("Generating components-version.yaml for operator")
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	operatorComponentsFilePath := operatorComponentsFilePath(outputDir)
	operatorComponentsFile, err := os.Create(operatorComponentsFilePath)
	if err != nil {
		return "", err
	}
	defer operatorComponentsFile.Close()
	if err = yaml.NewEncoder(operatorComponentsFile).Encode(pinnedversion[0]); err != nil {
		return "", err
	}
	return operatorComponentsFilePath, nil
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
func RetrievePinnedOperatorVersion(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedVersionFile PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedVersionFile); err != nil {
		return "", err
	}
	return pinnedVersionFile[0].TigeraOperator.Version, nil
}

// RetrieveReleaseName retrieves the release name from the pinned version file.
func RetrieveReleaseName(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].ReleaseName, nil
}

// RetrievePinnedCalicoVersion retrieves the calico version from the pinned version file.
func RetrievePinnedCalicoVersion(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Title, nil
}

// RetrievePinnedVersionNote retrieves the note from the pinned version file.
func RetrievePinnedVersionNote(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Note, nil
}

// RetrievePinnedVersionHash retrieves the hash from the pinned version file.
func RetrievePinnedVersionHash(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Hash, nil
}

// RetrieveComponentsToValidate retrieves the components to validate from the pinned version file.
func RetrieveComponentsToValidate(outputDir string) (map[string]Component, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersionFile
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return nil, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return nil, err
	}
	components := pinnedversion[0].Components
	components["tigera-operator"] = pinnedversion[0].TigeraOperator
	for name, component := range components {
		if name == "calico" || name == "networking-calico" {
			// Skip calico and networking-calico as they do not have images.
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
