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
	operatorDir := cfg.OperatorConfig.Dir
	componentsVersionPath, err := hashrelease.GenerateComponentsVersionFile(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate components.yaml")
	}
	operatorComponent, err := hashrelease.RetrievePinnedOperator(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	if err := operator.GenVersions(componentsVersionPath, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to generate versions")
	}
	logrus.Infof("Building operator images for %v", cfg.ValidArchs)
	if err := operator.ImageAll(cfg.ValidArchs, operatorComponent.Version, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to build images")
	}
	logrus.Info("Building operator init image")
	operatorInitImage := operatorComponent.InitImage()
	if err := operator.InitImage(operatorInitImage.Version, operatorDir); err != nil {
		logrus.WithError(err).Fatal("Failed to init images")
	}
	for _, arch := range cfg.ValidArchs {
		currentTag := fmt.Sprintf("%s:latest-%s", operatorComponent.Image, arch)
		newTag := fmt.Sprintf("%s-%s", operatorComponent.String(), arch)
		logrus.WithFields(logrus.Fields{
			"current tag": currentTag,
			"new tag":     newTag,
		}).Info("Re-tagging operator image")
		if err := runner.TagImage(currentTag, newTag); err != nil {
			logrus.WithField("image", currentTag).WithError(err).Fatal("Failed to re-tag operator image")
		}
	}
	logrus.Info("Re-tag operator init image")
	currentTag := fmt.Sprintf("%s:latest", operatorInitImage.Image)
	newTag := operatorComponent.InitImage().String()
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
	operatorComponent, err := hashrelease.RetrievePinnedOperator(cfg.OutputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	var imageList []string
	for _, arch := range cfg.ValidArchs {
		imgName := fmt.Sprintf("%s-%s", operatorComponent.String(), arch)
		if err := runner.PushImage(imgName); err != nil {
			logrus.WithField("image", imgName).WithError(err).Fatal("Failed to push operator image")
		}
		logrus.WithField("image", imgName).Info("Pushed operator image")
		imageList = append(imageList, imgName)
	}
	manifestListName := operatorComponent.String()
	if err = runner.ManifestPush(manifestListName, imageList); err != nil {
		logrus.WithField("manifest", manifestListName).WithError(err).Fatal("Failed to push operator manifest")
	}
	initImage := operatorComponent.InitImage()
	if err := runner.PushImage(initImage.String()); err != nil {
		logrus.WithField("image", initImage).WithError(err).Fatal("Failed to push operator init image")
	}
}
