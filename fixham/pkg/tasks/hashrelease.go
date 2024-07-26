package tasks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/fixham/internal/command"
	"github.com/projectcalico/calico/fixham/internal/config"
	"github.com/projectcalico/calico/fixham/internal/hashrelease"
	"github.com/projectcalico/calico/fixham/internal/operator"
	"github.com/projectcalico/calico/fixham/internal/registry"
	"github.com/projectcalico/calico/fixham/internal/release"
	"github.com/projectcalico/calico/fixham/internal/utils"
	"github.com/projectcalico/calico/fixham/internal/version"
)

// hashreleaseDir returns the path to where hashrelease directory
func hashreleaseDir(outputDir string) string {
	return filepath.Join(outputDir, "hashrelease")
}

// PinnedVersion generates pinned-version.yaml
//
// It clones the operator repository,
// then call GeneratePinnedVersion to generate the pinned-version.yaml file.
// The location of the pinned-version.yaml file is logged.
func PinnedVersion(cfg *config.Config) {
	outputDir := cfg.OutputDir
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logrus.WithError(err).Fatal("Failed to create output directory")
	}
	if err := operator.Clone(cfg.RepoRootDir, cfg.OperatorBranchName); err != nil {
		logrus.WithFields(logrus.Fields{
			"directory":       outputDir,
			"operator branch": cfg.OperatorBranchName,
		}).WithError(err).Fatal("Failed to clone operator repository")
	}
	pinnedVersionFilePath, err := hashrelease.GeneratePinnedVersionFile(cfg.RepoRootDir, cfg.DevTagSuffix, outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate pinned-version.yaml")
	}
	logrus.WithField("file", pinnedVersionFilePath).Info("Generated pinned-version.yaml")
}

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

// HashreleaseBuild builds the artificts hashrelease
//
// This includes the windows archive, helm archive, and manifests.
func HashreleaseBuild(cfg *config.Config) {
	outputDir := cfg.OutputDir
	hashreleaseOutputDir := hashreleaseDir(outputDir)
	dirty, err := utils.GitIsDirty(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to check if git is dirty")
	} else if dirty {
		logrus.Fatal("There are uncommitted changes in the repository, please commit or stash them before building the hashrelease")
	}
	if err := os.MkdirAll(hashreleaseOutputDir, 0755); err != nil {
		logrus.WithError(err).Fatal("Failed to create hashrelease directory")
	}
	releaseVersion, err := hashrelease.RetrievePinnedCalicoVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	if err := utils.ReleaseWindowsArchive(cfg.RepoRootDir, releaseVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to release windows archive")
	}
	if err := utils.HelmArchive(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to release helm archive")
	}
	if err := utils.GenerateManifests(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to generate manifests")
	}

	if err := release.Metadata(hashreleaseOutputDir, releaseVersion, operatorVersion); err != nil {
		logrus.WithError(err).Fatal("Failed to generate metadata")
	}
}

type imageExistsResult struct {
	exists bool
	err    error
	name   string
}

func imgExists(name string, component hashrelease.Component, ch chan imageExistsResult) {
	r := imageExistsResult{}
	if component.Image == "" {
		component.Image = name
	}
	exists, err := registry.ImageExists(component.ImageWithTag(), component.Registry)
	r.name = component.String()
	r.exists = exists
	r.err = err
	ch <- r
}

// HashreleaseValidate validates the images in the hashrelease.
// These images are checked to ensure they exist in the registry
// as they should have been pushed in the standard build process.
func HashreleaseValidate(cfg *config.Config) {
	pinnedVersion, err := hashrelease.RetrievePinnedVersion(cfg.OutputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version")
	}
	images := pinnedVersion.Components
	images["operator"] = pinnedVersion.TigeraOperator
	results := make(map[string]imageExistsResult, len(images))

	ch := make(chan imageExistsResult)
	for name, component := range images {
		go imgExists(name, component, ch)
	}
	for range images {
		res := <-ch
		results[res.name] = res
	}
	failedImages := []string{}
	for name, r := range results {
		logrus.WithFields(logrus.Fields{
			"image":  name,
			"exists": r.exists,
		}).Info("Image validation")
		if r.exists {
			logrus.WithField("image", name).Info("Image exists")
		} else {
			if r.err != nil {
				logrus.WithError(r.err).WithField("image", name).Error("Error checking image")
			}
			failedImages = append(failedImages, name)
		}
	}
	failedCount := len(failedImages)
	if failedCount > 0 {
		logrus.WithField("images", strings.Join(failedImages, ", ")).Fatalf("Failed to validate %d images, see above for details", failedCount)
	}
}

// HashreleaseValidate publishes the hashrelease
func HashreleasePush(cfg *config.Config) {
	outputDir := cfg.OutputDir
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	name, err := hashrelease.RetrieveReleaseName(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	note, err := hashrelease.RetrievePinnedVersionNote(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version note")
	}
	calicoVersion, err := hashrelease.RetrievePinnedCalicoVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	// TODO: send image to image scan server
	releaseHash, err := hashrelease.RetrievePinnedVersionHash(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release hash")
	}
	releaseVersion := version.Version(calicoVersion)
	logrus.WithField("note", note).Info("Publishing hashrelease")
	if err := hashrelease.PublishHashrelease(name, releaseHash, note, releaseVersion.Stream(), hashreleaseDir(outputDir), sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to publish hashrelease")
	}
}

// HashreleaseCleanRemote cleans up old hashreleases on the docs host
func HashreleaseCleanRemote(cfg *config.Config) {
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	logrus.Info("Cleaning up old hashreleases")
	if err := hashrelease.DeleteOldHashreleases(sshConfig, -1); err != nil {
		logrus.WithError(err).Fatal("Failed to delete old hashreleases")
	}
	// TODO: Consider cleaning up images in the release library file (NEW!)
}

// HashreleaseNotes generates the release notes for the hashrelease
func HashreleaseNotes(cfg *config.Config) {
	filePath, err := release.GenerateReleaseNotes(cfg.Organization, cfg.GithubToken, cfg.RepoRootDir, hashreleaseDir(cfg.OutputDir))
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate release notes")
	}
	logrus.WithField("file", filePath).Info("Generated release notes")
	logrus.Info("Please review for accuracy, and ensure properly formatted before relase time.")
}
