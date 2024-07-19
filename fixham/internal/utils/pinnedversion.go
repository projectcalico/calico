package utils

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/projectcalico/calico/fixham/internal/operator"
)

const (
	QuayRegistry              = "quay.io"
	pinnedVersionTemplatePath = "/fixham/assets/pinned-version.yaml.tmpl"
	pinnedVersionOutputPath   = "/calico/pinned-version.yaml"
	operatorComponentsPath    = "/fixham/assets/components.yaml"
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

func GeneratePinnedVersion(rootDir, devTagSuffix string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
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
	calicoBranch, err := GitBranch(rootDir)
	if err != nil {
		return "", err
	}
	calicoVersion, err := GitVersion(rootDir, devTagSuffix)
	if err != nil {
		return "", err
	}
	operatorBranch, err := operator.GitBranch(rootDir)
	if err != nil {
		return "", err
	}
	operatorVersion, err := operator.GitVersion(rootDir, devTagSuffix)
	if err != nil {
		return "", err
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

func GeneratePinnedVersionForOperator(rootDir string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
	logrus.WithField("pinned version file", pinnedVersionPath).Info("Generating components-version.yaml for operator")
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	operatorComponentsPath := rootDir + operatorComponentsPath
	operatorComponentsFile, err := os.Create(operatorComponentsPath)
	if err != nil {
		return "", err
	}
	defer operatorComponentsFile.Close()
	if err = yaml.NewEncoder(operatorComponentsFile).Encode(pinnedversion[0]); err != nil {
		return "", err
	}
	return operatorComponentsPath, nil
}

func RetrievePinnedOperatorVersion(rootDir string) (string, error) {
	operatorComponentsPath := rootDir + operatorComponentsPath
	logrus.WithField("operator components file", operatorComponentsPath).Debug("Reading components.yaml")
	operatorComponentsData, err := os.ReadFile(operatorComponentsPath)
	if err != nil {
		return "", err
	}
	var pinnedVersion PinnedVersion
	if err := yaml.Unmarshal(operatorComponentsData, &pinnedVersion); err != nil {
		return "", err
	}
	return pinnedVersion.TigeraOperator.Version, nil
}

func RetrieveReleaseName(rootDir string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].ReleaseName, nil
}

func RetrievePinnedCalicoVersion(rootDir string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Title, nil
}

func RetrievePinnedVersionNote(rootDir string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Note, nil
}

func RetrievePinnedVersionHash(rootDir string) (string, error) {
	pinnedVersionPath := rootDir + pinnedVersionOutputPath
	var pinnedversion = []PinnedVersion{}
	if pinnedVersionData, err := os.ReadFile(pinnedVersionPath); err != nil {
		return "", err
	} else if err := yaml.Unmarshal([]byte(pinnedVersionData), &pinnedversion); err != nil {
		return "", err
	}
	return pinnedversion[0].Hash, nil
}
