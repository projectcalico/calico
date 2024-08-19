package tasks

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashrelease"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

func CIURL() string {
	if os.Getenv("CI") == "true" && os.Getenv("SEMAPHORE") == "true" {
		return fmt.Sprintf("https://tigera.semaphoreci.com/workflows/%s", os.Getenv("SEMAPHORE_WORKFLOW_ID"))
	}
	return ""
}

// PinnedVersion generates pinned-version.yaml
//
// It clones the operator repository,
// then call GeneratePinnedVersion to generate the pinned-version.yaml file.
// The location of the pinned-version.yaml file is logged.
func PinnedVersion(cfg *config.Config) {
	outputDir := cfg.OutputDir
	if err := os.MkdirAll(outputDir, utils.DirPerms); err != nil {
		logrus.WithError(err).Fatal("Failed to create output directory")
	}
	operatorDir := operator.Dir(cfg.TmpFolderPath())
	if err := operator.Clone(operatorDir, cfg.OperatorBranchName); err != nil {
		logrus.WithFields(logrus.Fields{
			"directory":       outputDir,
			"operator branch": cfg.OperatorBranchName,
		}).WithError(err).Fatal("Failed to clone operator repository")
	}
	pinnedVersionFilePath, err := hashrelease.GeneratePinnedVersionFile(cfg.RepoRootDir, operatorDir, cfg.DevTagSuffix, cfg.Registry, outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate pinned-version.yaml")
	}
	logrus.WithField("file", pinnedVersionFilePath).Info("Generated pinned-version.yaml")
}

// HashreleaseBuild builds the artificts hashrelease
//
// This includes the windows archive, helm archive, and manifests.
func HashreleaseBuild(cfg *config.Config) {
	outputDir := cfg.OutputDir
	hashreleaseOutputDir := cfg.HashreleaseDir()
	if err := os.MkdirAll(hashreleaseOutputDir, utils.DirPerms); err != nil {
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
	if err := outputs.ReleaseWindowsArchive(cfg.RepoRootDir, releaseVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to release windows archive")
	}
	if err := outputs.HelmArchive(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to release helm archive")
	}
	if err := outputs.Manifests(cfg.RepoRootDir, releaseVersion, operatorVersion, hashreleaseOutputDir); err != nil {
		logrus.WithError(err).Fatal("Failed to generate manifests")
	}

	if err := outputs.Metadata(hashreleaseOutputDir, releaseVersion, operatorVersion); err != nil {
		logrus.WithError(err).Fatal("Failed to generate metadata")
	}
}

type imageExistsResult struct {
	name   string
	image  string
	exists bool
	err    error
}

func imgExists(name string, component hashrelease.Component, ch chan imageExistsResult) {
	r := imageExistsResult{
		name:  name,
		image: component.String(),
	}
	r.exists, r.err = registry.ImageExists(component.ImageRef())
	ch <- r
}

// HashreleaseValidate validates the images in the hashrelease.
// These images are checked to ensure they exist in the registry
// as they should have been pushed in the standard build process.
func HashreleaseValidate(cfg *config.Config) {
	outputDir := cfg.OutputDir
	name, err := hashrelease.RetrieveReleaseName(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	calicoVersion, err := hashrelease.RetrievePinnedCalicoVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	images, err := hashrelease.RetrieveComponentsToValidate(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version")
	}
	results := make(map[string]imageExistsResult, len(images))

	ch := make(chan imageExistsResult)
	for name, component := range images {
		go imgExists(name, component, ch)
	}
	for range images {
		res := <-ch
		results[res.name] = res
	}
	failedImages := []hashrelease.Component{}
	failedImageNames := []string{}
	for name, r := range results {
		logrus.WithFields(logrus.Fields{
			"image":  r.image,
			"exists": r.exists,
		}).Info("Validating image")
		if r.err != nil || !r.exists {
			logrus.WithError(r.err).WithField("image", name).Error("Error checking image")
			failedImageNames = append(failedImageNames, name)
			failedImages = append(failedImages, images[name])
		} else {
			logrus.WithField("image", name).Info("Image exists")
		}
	}
	failedCount := len(failedImageNames)
	if failedCount > 0 {
		ciURL := CIURL()
		// We only care to send failure messages if we are in CI
		if ciURL != "" {
			slackMsg := slack.Message{
				Channel: cfg.SlackChannel,
				Data: slack.MessageData{
					ReleaseName:     name,
					Product:         utils.DisplayProductName(),
					Branch:          version.Branch(calicoVersion, cfg.RepoReleaseBranchPrefix),
					Version:         calicoVersion,
					OperatorVersion: operatorVersion,
					CIURL:           ciURL,
					FailedImages:    failedImages,
				},
			}
			if err := slackMsg.SendFailure(cfg.SlackToken, logrus.IsLevelEnabled(logrus.DebugLevel)); err != nil {
				logrus.WithError(err).Error("Failed to send slack message")
			}
		}
		logrus.WithField("images", strings.Join(failedImageNames, ", ")).
			Fatalf("Failed to validate %d images, see above for details", failedCount)
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
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	releaseHash, err := hashrelease.RetrievePinnedVersionHash(outputDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release hash")
	}
	releaseVersion := version.Version(calicoVersion)
	logrus.WithField("note", note).Info("Publishing hashrelease")
	if err := hashrelease.PublishHashrelease(name, releaseHash, note, releaseVersion.Stream(), cfg.HashreleaseDir(), sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to publish hashrelease")
	}
	slackMsg := slack.Message{
		Channel: cfg.SlackChannel,
		Data: slack.MessageData{
			ReleaseName:     name,
			Product:         utils.DisplayProductName(),
			Branch:          version.Branch(calicoVersion, cfg.RepoReleaseBranchPrefix),
			Version:         calicoVersion,
			OperatorVersion: operatorVersion,
			DocsURL:         hashrelease.URL(name),
			CIURL:           CIURL(),
		},
	}
	if err := slackMsg.SendSuccess(cfg.SlackToken, logrus.IsLevelEnabled(logrus.DebugLevel)); err != nil {
		logrus.WithError(err).Error("Failed to send slack message")
	}
}

// HashreleaseCleanRemote cleans up old hashreleases on the docs host
func HashreleaseCleanRemote(cfg *config.Config) {
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	logrus.Info("Cleaning up old hashreleases")
	if err := hashrelease.DeleteOldHashreleases(sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to delete old hashreleases")
	}
}
