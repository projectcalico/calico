package tasks

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashrelease"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

// ciURL returns the URL for the CI job.
func ciURL() string {
	if os.Getenv("CI") == "true" && os.Getenv("SEMAPHORE") == "true" {
		return fmt.Sprintf("https://tigera.semaphoreci.com/jobs/%s", os.Getenv("SEMAPHORE_JOB_ID"))
	}
	return ""
}

// PinnedVersion generates pinned-version.yaml
//
// It clones the operator repository,
// then call GeneratePinnedVersion to generate the pinned-version.yaml file.
// The location of the pinned-version.yaml file is logged.
func PinnedVersion(cfg *config.Config) (string, string, string) {
	tmpDir := cfg.TmpFolderPath()
	if err := os.MkdirAll(tmpDir, utils.DirPerms); err != nil {
		logrus.WithError(err).Fatal("Failed to create output directory")
	}
	operatorConfig := cfg.OperatorConfig
	if err := operator.Clone(operatorConfig); err != nil {
		logrus.WithFields(logrus.Fields{
			"directory":  tmpDir,
			"repository": operatorConfig.Repo,
			"branch":     operatorConfig.Branch,
		}).WithError(err).Fatal("Failed to clone operator repository")
	}
	pinnedVersionFilePath, data, err := hashrelease.GeneratePinnedVersionFile(cfg.RepoRootDir, cfg.RepoReleaseBranchPrefix, cfg.DevTagSuffix, cfg.OperatorConfig, tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to generate pinned-version.yaml")
	}
	logrus.WithField("file", pinnedVersionFilePath).Info("Generated pinned-version.yaml")
	return data.ProductVersion, data.Operator.Version, data.Hash
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
func HashreleaseValidate(cfg *config.Config, skipISS bool) {
	tmpDir := cfg.TmpFolderPath()
	name, err := hashrelease.RetrieveReleaseName(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	productBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to get %s branch name", utils.ProductName)
	}
	productVersion, err := hashrelease.RetrievePinnedProductVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	parsedProductVersion := version.Version(productVersion)
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	images, err := hashrelease.RetrieveComponentsToValidate(tmpDir)
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
		ciURL := ciURL()
		// We only care to send failure messages if we are in CI
		if ciURL != "" {
			slackMsg := slack.Message{
				Config: cfg.SlackConfig,
				Data: slack.MessageData{
					ReleaseName:     name,
					Product:         utils.DisplayProductName(),
					Branch:          productBranch,
					Version:         productVersion,
					OperatorVersion: operatorVersion,
					CIURL:           ciURL,
					FailedImages:    failedImages,
				},
			}
			if err := slackMsg.SendFailure(logrus.IsLevelEnabled(logrus.DebugLevel)); err != nil {
				logrus.WithError(err).Error("Failed to send slack message")
			}
		}
		logrus.WithField("images", strings.Join(failedImageNames, ", ")).
			Fatalf("Failed to validate %d images, see above for details", failedCount)
	}
	if !skipISS {
		logrus.Info("Sending images to ISS")
		imageList := []string{}
		for _, component := range images {
			imageList = append(imageList, component.String())
		}
		imageScanner := imagescanner.New(cfg.ImageScannerConfig)
		err := imageScanner.Scan(imageList, parsedProductVersion.Stream(), false, cfg.OutputDir)
		if err != nil {
			// Error is logged and ignored as this is not considered a fatal error
			logrus.WithError(err).Error("Failed to scan images")
		}
	}
}

// CheckIfHashReleasePublished checks if the hashrelease has already been published.
// If it has, the process is halted.
func CheckIfHashReleasePublished(cfg *config.Config, hash string) {
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	if hashrelease.Exists(hash, sshConfig) {
		logrus.WithField("hash", hash).Fatal("Hashrelease already exists")
	}
}

// HashreleaseValidate publishes the hashrelease
func HashreleasePush(cfg *config.Config, path string) {
	tmpDir := cfg.TmpFolderPath()
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	name, err := hashrelease.RetrieveReleaseName(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	note, err := hashrelease.RetrievePinnedVersionNote(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version note")
	}
	productBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to get %s branch name", utils.ProductName)
	}
	productVersion, err := hashrelease.RetrievePinnedProductVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := hashrelease.RetrievePinnedOperatorVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	releaseHash, err := hashrelease.RetrievePinnedVersionHash(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release hash")
	}
	logrus.WithField("note", note).Info("Publishing hashrelease")
	if err := hashrelease.Publish(name, releaseHash, note, productBranch, path, sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to publish hashrelease")
	}
	scanResultURL := imagescanner.RetrieveResultURL(cfg.OutputDir)
	slackMsg := slack.Message{
		Config: cfg.SlackConfig,
		Data: slack.MessageData{
			ReleaseName:        name,
			Product:            utils.DisplayProductName(),
			Branch:             productBranch,
			Version:            productVersion,
			OperatorVersion:    operatorVersion,
			DocsURL:            hashrelease.URL(name),
			CIURL:              ciURL(),
			ImageScanResultURL: scanResultURL,
		},
	}
	if err := slackMsg.SendSuccess(logrus.IsLevelEnabled(logrus.DebugLevel)); err != nil {
		logrus.WithError(err).Error("Failed to send slack message")
	}
	logrus.WithFields(logrus.Fields{
		"name":    name,
		"docsURL": hashrelease.URL(name),
	}).Info("Published hashrelease")
}

// HashreleaseCleanRemote cleans up old hashreleases on the docs host
func HashreleaseCleanRemote(cfg *config.Config) {
	sshConfig := command.NewSSHConfig(cfg.DocsHost, cfg.DocsUser, cfg.DocsKey, cfg.DocsPort)
	logrus.Info("Cleaning up old hashreleases")
	if err := hashrelease.DeleteOld(sshConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to delete old hashreleases")
	}
}
