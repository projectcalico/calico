package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	ProductName = "calico"
)

// GitBranch returns the current git branch of the repository.
func GitBranch(dir string) (string, error) {
	return command.GitInDir(dir, "rev-parse", "--abbrev-ref", "HEAD")
}

// GitVersion returns the current git version of the repository.
func GitVersion(dir string) (string, error) {
	return command.GitVersion(dir, false)
}

// GitIsDirty returns true if the repository is dirty.
func GitIsDirty(dir string) (bool, error) {
	version, err := command.GitVersion(dir, true)
	if err != nil {
		return false, err
	}
	return strings.HasSuffix(version, "-dirty"), nil
}

// ReleaseWindowsArchive generates the windows archive for the release.
func ReleaseWindowsArchive(rootDir, calicoVersion, outDir string) error {
	outDir = filepath.Join(outDir, "files", "windows")
	env := os.Environ()
	env = append(env, fmt.Sprintf("VERSION=%s", calicoVersion))
	if _, err := command.MakeInDir(filepath.Join(rootDir, "node"), []string{"release-windows-archive"}, env); err != nil {
		logrus.WithError(err).Error("Failed to make release-windows-archive")
		return err
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		logrus.WithError(err).Error("Failed to create windows output directory")
	}
	fileName := fmt.Sprintf("calico-windows-%s.zip", calicoVersion)
	if err := MoveFile(filepath.Join(rootDir, "node", "dist", fileName), filepath.Join(outDir, fileName)); err != nil {
		logrus.WithError(err).Error("Failed to move generated windows archive to output directory")
		return err
	}
	return nil
}

// HelmArchive generates the helm archive for the release.
func HelmArchive(rootDir, calicoVersion, operatorVersion, outDir string) error {
	tigeraOperatorChartValuesFilePath := filepath.Join(rootDir, "charts", "tigera-operator", "values.yaml")
	if _, err := command.Run("sed", []string{"-i", fmt.Sprintf(`s/version: .*/version: %s/g`, operatorVersion), tigeraOperatorChartValuesFilePath}); err != nil {
		logrus.WithError(err).Error("Failed to update operator version in values.yaml")
		return err
	}
	if _, err := command.Run("sed", []string{"-i", fmt.Sprintf(`s/tag: .*/tag: %s/g`, calicoVersion), rootDir + tigeraOperatorChartValuesFilePath}); err != nil {
		logrus.WithError(err).Error("Failed to update calicoctl version in values.yaml")
		return err
	}
	if _, err := command.MakeInDir(rootDir, []string{"chart"}, os.Environ()); err != nil {
		logrus.WithError(err).Error("Failed to make helm chart")
		return err
	}
	if err := MoveFile(fmt.Sprintf(`%s/bin/tigera-operator-v*.tgz`, rootDir), filepath.Join(outDir, "tigera-operator.tgz")); err != nil {
		logrus.WithError(err).Error("Failed to move generated helm chart to output directory")
		return err
	}

	if _, err := command.GitInDir(rootDir, "checkout", "charts/tigera-operator"); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to charts")
		return err
	}
	return nil
}

// GenerateManifests generates the manifests for the release.
func GenerateManifests(rootDir, calicoVersion, operatorVersion, outDir string) error {
	env := os.Environ()
	env = append(env, fmt.Sprintf("CALICO_VERSION=%s", calicoVersion))
	env = append(env, fmt.Sprintf("OPERATOR_VERSION=%s", operatorVersion))
	if _, err := command.MakeInDir(rootDir, []string{"gen-manifests"}, env); err != nil {
		logrus.WithError(err).Error("Failed to make manifests")
		return err
	}
	manifestDir := filepath.Join(outDir, "manifests")
	if _, err := command.Run("cp", []string{"-r", manifestDir, outDir}); err != nil {
		logrus.WithError(err).Error("Failed to copy manifests to output directory")
		return err
	}
	if _, err := command.MakeInDir(rootDir, []string{"bin/ocp.tgz"}, os.Environ()); err != nil {
		logrus.WithError(err).Error("Failed to make openshift manifests archive")
		return err
	}
	fileName := "ocp.tgz"
	if err := MoveFile(filepath.Join(rootDir, "bin", fileName), filepath.Join(manifestDir, fileName)); err != nil {
		logrus.WithError(err).Error("Failed to copy openshift manifests archive to output directory")
		return err
	}
	if _, err := command.GitInDir(rootDir, "checkout", "manifests/"); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to manifests")
		return err
	}
	return nil
}
