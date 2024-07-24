package utils

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
)

const (
	ProductName = "calico"
)

func GitBranch(dir string) (string, error) {
	return command.GitInDir(dir, "rev-parse", "--abbrev-ref", "HEAD")
}

func GitVersion(dir string) (string, error) {
	return command.GitVersion(dir, false)
}

func GitVersionDirty(dir, devTagSuffix string) (string, error) {
	return command.GitVersion(dir, true)
}

func ReleaseWindowsArchive(rootDir, calicoVersion, outDir string) error {
	env := os.Environ()
	env = append(env, "VERSION="+calicoVersion)
	if _, err := command.MakeInDir(rootDir+"/node", []string{"release-windows-archive"}, env); err != nil {
		logrus.WithError(err).Error("Failed to make release-windows-archive")
		return err
	}
	if err := CreateDir(outDir); err != nil {
		logrus.WithError(err).Error("Failed to create windows output directory")
	}
	if _, err := command.Run("mv", []string{rootDir + "/node/dist/calico-windows-" + calicoVersion + ".zip", outDir}); err != nil {
		logrus.WithError(err).Error("Failed to move generated windows archive to output directory")
		return err
	}
	return nil
}

func HelmArchive(rootDir, calicoVersion, operatorVersion, outDir string) error {
	if _, err := command.Run("sed", []string{"-i", fmt.Sprintf("'s/version: .*/version: %s/g'", operatorVersion), rootDir + "/charts/tigera-operator/values.yaml"}); err != nil {
		logrus.WithError(err).Error("Failed to update operator version in values.yaml")
		return err
	}
	if _, err := command.Run("sed", []string{"-i", fmt.Sprintf("'s/tag: .*/tag: %s/g'", calicoVersion), rootDir + "/charts/tigera-operator/values.yaml"}); err != nil {
		logrus.WithError(err).Error("Failed to update calicoctl version in values.yaml")
		return err
	}
	if _, err := command.MakeInDir(rootDir, []string{"chart"}, os.Environ()); err != nil {
		logrus.WithError(err).Error("Failed to make helm chart")
		return err
	}
	if _, err := command.Run("mv", []string{rootDir + "bin/tigera-operator-v*.tgz", outDir + "/tigera-operator-v*.tgz"}); err != nil {
		logrus.WithError(err).Error("Failed to move generated helm chart to output directory")
		return err
	}

	if _, err := command.GitInDir(rootDir, "checkout", "charts/tigera-operator"); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to charts")
		return err
	}
	return nil
}

func GenerateManifests(rootDir, calicoVersion, operatorVersion, outDir string) error {
	env := os.Environ()
	env = append(env, "CALICO_VERSION="+calicoVersion)
	env = append(env, "OPERATOR_VERSION="+operatorVersion)
	if _, err := command.MakeInDir(rootDir, []string{"gen-manifests"}, env); err != nil {
		logrus.WithError(err).Error("Failed to make manifests")
		return err
	}
	if _, err := command.Run("mv", []string{rootDir + "/manifests", outDir}); err != nil {
		logrus.WithError(err).Error("Failed to copy manifests to output directory")
		return err
	}
	if _, err := command.MakeInDir(rootDir, []string{"bin/ocp.tgz"}, os.Environ()); err != nil {
		logrus.WithError(err).Error("Failed to make openshift manifests archive")
		return err
	}
	if _, err := command.Run("mv", []string{rootDir + "/bin/ocp.tgz", outDir + "/manifests"}); err != nil {
		logrus.WithError(err).Error("Failed to copy openshift manifests archive to output directory")
		return err
	}
	if _, err := command.GitInDir(rootDir, "checkout", "manifests/"); err != nil {
		logrus.WithError(err).Error("Failed to reset changes to manifests")
		return err
	}
	return nil
}
