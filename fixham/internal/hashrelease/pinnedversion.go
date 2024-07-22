package hashrelease

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/fixham/internal/operator"
	"github.com/projectcalico/calico/fixham/internal/utils"
	"github.com/projectcalico/calico/fixham/internal/version"
)

const (
	pinnedVersionTemplatePath  = "/fixham/assets/pinned-version.yaml.tmpl"
	pinnedVersionFileName      = "pinned-version.yaml"
	operatorComponentsFileName = "components.yaml"
)

type Component struct {
	Version  string `yaml:"version"`
	Image    string `yaml:"image,omitempty"`
	Registry string `yaml:"registry,omitempty"`
}

type PinnedVersionData struct {
	ReleaseName   string
	CalicoVersion string
	Operator      Component
	Note          string
	Hash          string
}

type PinnedVersion struct {
	Title          string               `yaml:"title"`
	ReleaseName    string               `yaml:"release_name"`
	Hash           string               `yaml:"full_hash"`
	Note           string               `yaml:"note"`
	ManifestURL    string               `yaml:"manifest_url"`
	TigeraOperator Component            `yaml:"tigera-operator"`
	Components     map[string]Component `yaml:"components"`
}

func pinnedVersionFilePath(outputDir string) string {
	return outputDir + "/" + pinnedVersionFileName
}

func operatorComponentsFilePath(outputDir string) string {
	return outputDir + "/" + operatorComponentsFileName
}

func GeneratePinnedVersion(rootDir, devTagSuffix, outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	if _, err := os.Stat(pinnedVersionPath); err == nil {
		logrus.WithField("pinned version file", pinnedVersionPath).Info("Pinned version file already exists")
		return pinnedVersionPath, fmt.Errorf("pinned version file already exists")
	}
	pinnedVersionTemplatePath := rootDir + pinnedVersionTemplatePath
	logrus.WithField("pinned version template", pinnedVersionTemplatePath).Debug("Reading pinned-version.yaml.tmpl")
	pinnedVersionTemplateData, err := os.ReadFile(pinnedVersionTemplatePath)
	if err != nil {
		return "", err
	}
	releaseName := fmt.Sprintf("%s-%s", time.Now().Format("2006-01-02"), RandomWord())
	calicoBranch, err := utils.GitBranch(rootDir)
	if err != nil {
		return "", err
	}
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
	logrus.WithField("pinned version file", pinnedVersionPath).Info("Generating pinned-version.yaml")
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

func GeneratePinnedVersionForOperator(rootDir, outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	logrus.WithField("pinned version file", pinnedVersionPath).Info("Generating components-version.yaml for operator")
	var pinnedversion = []PinnedVersion{}
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

func RetrievePinnedVersion(outputDir string) (PinnedVersion, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion PinnedVersion
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return pinnedversion, err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return pinnedversion, err
	}
	return pinnedversion, nil
}

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

func RetrieveReleaseName(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].ReleaseName, nil
}

func RetrievePinnedCalicoVersion(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Title, nil
}

func RetrievePinnedVersionNote(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Note, nil
}

func RetrievePinnedVersionHash(outputDir string) (string, error) {
	pinnedVersionPath := pinnedVersionFilePath(outputDir)
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Hash, nil
}
