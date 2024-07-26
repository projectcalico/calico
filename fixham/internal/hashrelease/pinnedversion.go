package hashrelease

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/fixham/internal/operator"
	"github.com/projectcalico/calico/fixham/internal/registry"
	"github.com/projectcalico/calico/fixham/internal/utils"
	"github.com/projectcalico/calico/fixham/internal/version"
)

const (
	pinnedVersionFileName      = "pinned-version.yaml"
	operatorComponentsFileName = "components.yaml"
)

func pinnedVersionTemplatePath(repoRootDir string) string {
	return filepath.Join(repoRootDir, utils.ReleaseFolderName, "assets", "pinned-version.yaml.tmpl")
}

// Component represents a component in the pinned version file.
type Component struct {
	Version  string `yaml:"version"`
	Image    string `yaml:"image,omitempty"`
	Registry string `yaml:"registry,omitempty"`
}

// ImageWithTag returns the image with the tag appended.
func (c Component) ImageWithTag() string {
	return fmt.Sprintf("%s:%s", c.Image, c.Version)
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
func GeneratePinnedVersionFile(rootDir, devTagSuffix, outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	if _, err := os.Stat(pinnedVersionPath); err == nil {
		logrus.WithField("file", pinnedVersionPath).Info("Pinned version file already exists")
		return pinnedVersionPath, fmt.Errorf("pinned version file already exists")
	}
	pinnedVersionTemplatePath := pinnedVersionTemplatePath(rootDir)
	logrus.WithField("template", pinnedVersionTemplatePath).Debug("Reading pinned-version.yaml.tmpl")
	pinnedVersionTemplateData, err := os.ReadFile(pinnedVersionTemplatePath)
	if err != nil {
		return "", err
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
	operatorBranch, err := operator.GitBranch(rootDir)
	if err != nil {
		return "", err
	}
	operatorVersion, err := operator.GitVersion(rootDir)
	if err != nil {
		return "", err
	}
	if !version.IsDevVersion(operatorVersion, devTagSuffix) {
		return "", fmt.Errorf("operator version %s does not have dev tag %s", operatorVersion, devTagSuffix)
	}
	tmpl, err := template.New("pinnedversion").Parse(string(pinnedVersionTemplateData))
	if err != nil {
		return "", err
	}
	data := &PinnedVersionData{
		ReleaseName:   releaseName,
		CalicoVersion: calicoVersion,
		Operator: Component{
			Version: operatorVersion + "-" + releaseName,
			Image:   operator.ImageName,
		},
		Hash: calicoVersion + "-" + operatorVersion,
		Note: fmt.Sprintf("%s - generated at %s using %s release branch with %s operator branch",
			releaseName, time.Now().Format(time.RFC1123), calicoBranch, operatorBranch),
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
func GenerateComponentsVersionFile(rootDir, outputDir string) (string, error) {
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

// RetrievePinnedComponents retrieves the operator version from the pinned version file.
func RetrievePinnedOperatorVersion(outputDir string) (string, error) {
	operatorComponentsFilePath := operatorComponentsFilePath(outputDir)
	operatorComponentsData, err := os.ReadFile(operatorComponentsFilePath)
	if err != nil {
		return "", err
	}
	var pinnedVersion PinnedVersion
	if err := yaml.Unmarshal(operatorComponentsData, &pinnedVersion); err != nil {
		return "", err
	}
	return pinnedVersion.TigeraOperator.Version, nil
}

// RetrievePinnedComponents retrieves the release name from the pinned version file.
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

// RetrievePinnedComponents retrieves the calico version from the pinned version file.
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
