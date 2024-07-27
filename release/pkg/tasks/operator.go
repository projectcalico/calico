package tasks

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashrelease"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/registry"
)

// OperatorHashreleaseBuild builds the operator images for the hashrelease.
// As images are build with the latest tag, they are re-tagged with the hashrelease version
func OperatorHashreleaseBuild(runner *registry.DockerRunner, cfg *config.Config) {
	outputDir := cfg.OutputDir
	repoRootDir := cfg.RepoRootDir
	componentsVersionPath, err := hashrelease.GenerateComponentsVersionFile(repoRootDir, outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate components.yaml")
	}
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	if err := operator.GenVersions(repoRootDir, componentsVersionPath); err != nil {
		logrus.WithError(err).Fatal("Failed to generate versions")
	}
	logrus.Infof("Building operator images for %v", cfg.ValidArchs)
	if err := operator.ImageAll(cfg.ValidArchs, operatorVersion, repoRootDir); err != nil {
		logrus.WithError(err).Fatal("Failed to build images")
	}
	logrus.Info("Building operator init image")
	if err := operator.InitImage(operatorVersion, repoRootDir); err != nil {
		logrus.WithError(err).Fatal("Failed to init images")
	}
	for _, arch := range cfg.ValidArchs {
		currentTag := fmt.Sprintf("%s:latest-%s", operator.ImageName, arch)
		newTag := fmt.Sprintf("%s/%s:%s-%s", registry.QuayRegistry, operator.ImageName, operatorVersion, arch)
		logrus.WithFields(logrus.Fields{
			"current tag": currentTag,
			"new tag":     newTag,
		}).Info("Re-tagging operator image")
		if err := runner.TagImage(currentTag, newTag); err != nil {
			logrus.WithField("image", currentTag).WithError(err).Fatal("Failed to re-tag operator image")
		}
	}
	logrus.Info("Re-tag operator init image")
	if err := runner.TagImage(fmt.Sprintf("%s-init:latest", operator.ImageName),
		fmt.Sprintf("%s/%s-init:%s", registry.QuayRegistry, operator.ImageName, operatorVersion)); err != nil {
		logrus.WithError(err).Fatal("Failed to tag operator init image")
	}
}

// OperatorHashreleasePush pushes the operator images to the registry
//
// It does this by retrieving the pinned operator version,
// pushing the operator images to the registry,
// then pushing a manifest list of the operator images to the registry.
func OperatorHashreleasePush(runner *registry.DockerRunner, cfg *config.Config) {
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(cfg.OutputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	var imageList []string
	for _, arch := range cfg.ValidArchs {
		imgName := fmt.Sprintf("%s/%s:%s-%s", registry.QuayRegistry, operator.ImageName, operatorVersion, arch)
		if err := runner.PushImage(imgName); err != nil {
			logrus.WithField("arch", arch).WithError(err).Fatal("Failed to push operator image")
		}
		imageList = append(imageList, imgName)
	}
	manifestListName := fmt.Sprintf("%s/%s:%s", registry.QuayRegistry, operator.ImageName, operatorVersion)
	if err = runner.ManifestPush(manifestListName, imageList, true); err != nil {
		logrus.WithField("manifest", manifestListName).WithError(err).Fatal("Failed to push operator manifest")
	}
	if err := runner.PushImage(fmt.Sprintf("%s/%s-init:%s", registry.QuayRegistry, operator.ImageName, operatorVersion)); err != nil {
		logrus.WithError(err).Fatal("Failed to push operator init image")
	}
}
