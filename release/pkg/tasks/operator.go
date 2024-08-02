package tasks

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashrelease"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/registry"
)

// getOperatorRepoDetails returns the registry and image name for the operator images.
// When a registry is specified in the config, the image name is modified and the registry is used
func getOperatorRepoDetails(cfg *config.Config) (string, string) {
	registry := operator.Registry
	imageName := operator.ImageName
	if cfg.Registry != "" {
		registry = cfg.Registry
		imageName = strings.ReplaceAll(imageName, "/", "-")
	}
	return registry, imageName
}

// OperatorHashreleaseBuild builds the operator images for the hashrelease.
// As images are build with the latest tag, they are re-tagged with the hashrelease version
func OperatorHashreleaseBuild(runner *registry.DockerRunner, cfg *config.Config) {
	outputDir := cfg.OutputDir
	operatorDir := operator.Dir(cfg.TmpFolderPath())
	componentsVersionPath, err := hashrelease.GenerateComponentsVersionFile(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate components.yaml")
	}
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	if err := operator.GenVersions(componentsVersionPath, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to generate versions")
	}
	logrus.Infof("Building operator images for %v", cfg.ValidArchs)
	if err := operator.ImageAll(cfg.ValidArchs, operatorVersion, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to build images")
	}
	logrus.Info("Building operator init image")
	if err := operator.InitImage(operatorVersion, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to init images")
	}
	registry, imageName := getOperatorRepoDetails(cfg)
	for _, arch := range cfg.ValidArchs {
		currentTag := fmt.Sprintf("%s:latest-%s", operator.ImageName, arch)
		newTag := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, operatorVersion, arch)
		logrus.WithFields(logrus.Fields{
			"current tag": currentTag,
			"new tag":     newTag,
		}).Info("Re-tagging operator image")
		if err := runner.TagImage(currentTag, newTag); err != nil {
			logrus.WithField("image", currentTag).WithError(err).Fatal("Failed to re-tag operator image")
		}
	}
	logrus.Info("Re-tag operator init image")
	currentTag := fmt.Sprintf("%s-init:latest", operator.ImageName)
	newTag := fmt.Sprintf("%s/%s-init:%s", registry, imageName, operatorVersion)
	if err := runner.TagImage(currentTag, newTag); err != nil {
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
	registry, imageName := getOperatorRepoDetails(cfg)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	var imageList []string
	for _, arch := range cfg.ValidArchs {
		imgName := fmt.Sprintf("%s/%s:%s-%s", registry, imageName, operatorVersion, arch)
		if err := runner.PushImage(imgName); err != nil {
			logrus.WithField("image", imgName).WithError(err).Fatal("Failed to push operator image")
		}
		logrus.WithField("image", imgName).Info("Pushed operator image")
		imageList = append(imageList, imgName)
	}
	manifestListName := fmt.Sprintf("%s/%s:%s", registry, imageName, operatorVersion)
	if err = runner.ManifestPush(manifestListName, imageList); err != nil {
		logrus.WithField("manifest", manifestListName).WithError(err).Fatal("Failed to push operator manifest")
	}
	imgName := fmt.Sprintf("%s/%s-init:%s", registry, imageName, operatorVersion)
	if err := runner.PushImage(imgName); err != nil {
		logrus.WithField("image", imgName).WithError(err).Fatal("Failed to push operator init image")
	}
}
