package tasks

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/calico"
	"github.com/projectcalico/calico/fixham/internal/command"
	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/docker"
	"github.com/projectcalico/calico/fixham/internal/docs"
	"github.com/projectcalico/calico/fixham/internal/operator"
	"github.com/projectcalico/calico/fixham/internal/version"
)

func hashreleaseDir(rootDir string) string {
	return rootDir + "/hashrelease"
}

func PinnedVersion(cfg *config.Config) {
	if err := operator.Clone(cfg.RepoRootDir, cfg.OperatorBranchName); err != nil {
		logrus.WithFields(logrus.Fields{
			"root directory":  cfg.RepoRootDir,
			"operator branch": cfg.OperatorBranchName,
		}).WithError(err).Fatal("Failed to clone operator repository")
	}
	pinnedVersionFilePath, err := calico.GeneratePinnedVersion(cfg.RepoRootDir, cfg.DevTagSuffix)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate pinned-version.yaml")
	}
	logrus.WithField("pinned version file", pinnedVersionFilePath).Info("Generated pinned-version.yaml")
}

func OperatorHashreleaseBuild(runner *docker.DockerRunner, cfg *config.Config) {
	componentsVersionPath, err := calico.GeneratePinnedVersionForOperator(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate components.yaml")
	}
	operatorVersion, err := calico.GetPinnedOperatorVersion(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	if err := operator.GenVersion(cfg.RepoRootDir, componentsVersionPath); err != nil {
		logrus.WithError(err).Fatal("Failed to generate versions")
	}
	logrus.Info("Building operator images")
	if err := operator.ImageAll(cfg.ValidArchs, cfg.GoBuildVersion); err != nil {
		logrus.WithError(err).Fatal("Failed to build images")
	}
	logrus.Info("Building operator init image")
	if err := operator.InitImage(cfg.GoBuildVersion); err != nil {
		logrus.WithError(err).Fatal("Failed to init images")
	}
	logrus.Info("Publishing operator images")
	for _, arch := range cfg.ValidArchs {
		if err := runner.TagImage(fmt.Sprintf("%s:latest-%s", operator.ImageName, arch),
			fmt.Sprintf("%s/%s:%s-%s", calico.QuayRegistry, operator.ImageName, operatorVersion, arch)); err != nil {
			logrus.WithField("arch", arch).WithError(err).Fatal("Failed to tag operator image")
		}
	}
	logrus.Info("Publishing operator init image")
	if err := runner.TagImage(fmt.Sprintf("%s-init:latest", operator.ImageName),
		fmt.Sprintf("%s/%s-init:%s", calico.QuayRegistry, operator.ImageName, operatorVersion)); err != nil {
		logrus.WithError(err).Fatal("Failed to tag operator init image")
	}
}

func OperatorHashreleasePush(runner *docker.DockerRunner, cfg *config.Config) {
	operatorVersion, err := calico.GetPinnedOperatorVersion(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	var imageList []string
	for _, arch := range cfg.ValidArchs {
		imgName := fmt.Sprintf("%s/%s:%s-%s", calico.QuayRegistry, operator.ImageName, operatorVersion, arch)
		if err := runner.PushImage(imgName); err != nil {
			logrus.WithField("arch", arch).WithError(err).Fatal("Failed to push operator image")
		}
		imageList = append(imageList, imgName)
	}
	manifestListName := fmt.Sprintf("%s/%s:%s", calico.QuayRegistry, operator.ImageName, operatorVersion)
	if err = runner.ManifestPush(manifestListName, imageList, true); err != nil {
		logrus.WithField("manifest list", manifestListName).WithError(err).Fatal("Failed to push operator manifest")
	}
	if err := runner.PushImage(fmt.Sprintf("%s/%s-init:%s", calico.QuayRegistry, operator.ImageName, operatorVersion)); err != nil {
		logrus.WithError(err).Fatal("Failed to push operator init image")
	}
}

func HashreleaseBuild(cfg *config.Config) {
	// TODO: ensure no changes in branch
	if err := os.MkdirAll(hashreleaseDir(cfg.RepoRootDir), os.ModePerm); err != nil {
		logrus.WithError(err).Fatal("Failed to create hashrelease directory")
	}
	releaseVersion, err := calico.GetPinnedVersion(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := calico.GetPinnedOperatorVersion(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	// TODO: generate release notes to hashrelease/release-notes
	if err := calico.ReleaseWindowsArchive(cfg.RepoRootDir, releaseVersion, hashreleaseDir(cfg.RepoRootDir)+"/files/windows"); err != nil {
		logrus.WithError(err).Fatal("Failed to release windows archive")
	}
	if err := calico.HelmArchive(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseDir(cfg.RepoRootDir)); err != nil {
		logrus.WithError(err).Fatal("Failed to release helm archive")
	}
	if err := calico.GenerateManifests(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseDir(cfg.RepoRootDir)); err != nil {
		logrus.WithError(err).Fatal("Failed to generate manifests")
	}

	if err := command.Metadata(hashreleaseDir(cfg.RepoRootDir), releaseVersion, operatorVersion); err != nil {
		logrus.WithError(err).Fatal("Failed to generate metadata")
	}
}

func HashreleasePush(cfg *config.Config) {
	sshConfig := &docs.SSHConfig{
		Host:    cfg.DocsHost,
		User:    cfg.DocsUser,
		KeyPath: cfg.DocsKey,
		Port:    cfg.DocsPort,
	}
	if host == "" {
		logrus.Fatal("Docs host is not set")
	}
	name, err := calico.GetReleaseName(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	note, err := calico.GetPinnedVersionNote(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version note")
	}
	releaseVersion, err := calico.GetPinnedVersion(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	_releaseVersion := version.Version(releaseVersion)
	// TODO: send image to image scan server
	// TODO: ensure release does not exist in server
	logrus.WithField("note", note).Info("Publishing hashrelease")
	if err := docs.PublishHashrelease(name, _releaseVersion.Stream(), hashreleaseDir(cfg.RepoRootDir), sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to publish hashrelease")
	}
}

func HashreleaseClean(cfg *config.Config) {
	sshConfig := &docs.SSHConfig{
		Host:    cfg.DocsHost,
		User:    cfg.DocsUser,
		KeyPath: cfg.DocsKey,
		Port:    cfg.DocsPort,
	}
	logrus.Info("Cleaning up old hashreleases")
	if err := docs.DeleteOldHashreleases(sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to delete old hashreleases")
	}
}
