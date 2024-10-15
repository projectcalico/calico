// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tasks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/config"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/pinnedversion"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

type imageExistsResult struct {
	name   string
	image  string
	exists bool
	err    error
}

func imgExists(name string, component registry.Component, ch chan imageExistsResult) {
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
	name, err := pinnedversion.RetrieveReleaseName(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	productBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to get %s branch name", utils.ProductName)
	}
	productVersion, err := pinnedversion.RetrievePinnedProductVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := pinnedversion.RetrievePinnedOperatorVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	images, err := pinnedversion.RetrieveComponentsToValidate(tmpDir)
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
	failedImages := []registry.Component{}
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
		// We only care to send failure messages if we are in CI
		if cfg.CI.IsCI {
			slackMsg := slack.Message{
				Config: cfg.SlackConfig,
				Data: slack.MessageData{
					ReleaseName:     name,
					Product:         utils.DisplayProductName(),
					Stream:          version.DeterminePublishStream(productBranch, productVersion),
					Version:         productVersion,
					OperatorVersion: operatorVersion,
					CIURL:           cfg.CI.URL(),
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
		err := imageScanner.Scan(imageList, version.DeterminePublishStream(productBranch, productVersion), false, cfg.OutputDir)
		if err != nil {
			// Error is logged and ignored as this is not considered a fatal error
			logrus.WithError(err).Error("Failed to scan images")
		}
	}
}

// HashreleasePublished checks if the hashrelease has already been published.
// If it has, the process is halted.
func HashreleasePublished(cfg *config.Config, hash string) (bool, error) {
	if !cfg.HashreleaseServerConfig.Valid() {
		// Check if we're running in CI - if so, we should fail if this configuration is missing.
		// Otherwise, we should just log and continue.
		if cfg.CI.IsCI {
			return false, fmt.Errorf("missing hashrelease server configuration")
		}
		logrus.Info("Missing hashrelease server configuration, skipping remote hashrelease check")
		return false, nil
	}

	return hashreleaseserver.HasHashrelease(hash, &cfg.HashreleaseServerConfig), nil
}

// HashreleaseValidate publishes the hashrelease
func HashreleasePush(cfg *config.Config, path string, setLatest bool) {
	tmpDir := cfg.TmpFolderPath()
	name, err := pinnedversion.RetrieveReleaseName(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release name")
	}
	note, err := pinnedversion.RetrievePinnedVersionNote(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get pinned version note")
	}
	productBranch, err := utils.GitBranch(cfg.RepoRootDir)
	if err != nil {
		logrus.WithError(err).Fatalf("Failed to get %s branch name", utils.ProductName)
	}
	productVersion, err := pinnedversion.RetrievePinnedProductVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get candidate name")
	}
	operatorVersion, err := pinnedversion.RetrievePinnedOperatorVersion(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get operator version")
	}
	releaseHash, err := pinnedversion.RetrievePinnedVersionHash(tmpDir)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get release hash")
	}
	hashrel := hashreleaseserver.Hashrelease{
		Name:   name,
		Hash:   releaseHash,
		Note:   note,
		Stream: version.DeterminePublishStream(productBranch, productVersion),
		Source: path,
		Latest: setLatest,
	}
	logrus.WithField("note", note).Info("Publishing hashrelease")
	if err := hashreleaseserver.PublishHashrelease(hashrel, &cfg.HashreleaseServerConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to publish hashrelease")
	}
	scanResultURL := imagescanner.RetrieveResultURL(cfg.OutputDir)
	slackMsg := slack.Message{
		Config: cfg.SlackConfig,
		Data: slack.MessageData{
			ReleaseName:        name,
			Product:            utils.DisplayProductName(),
			Stream:             version.DeterminePublishStream(productBranch, productVersion),
			Version:            productVersion,
			OperatorVersion:    operatorVersion,
			DocsURL:            hashrel.URL(),
			CIURL:              cfg.CI.URL(),
			ImageScanResultURL: scanResultURL,
		},
	}
	if err := slackMsg.SendSuccess(logrus.IsLevelEnabled(logrus.DebugLevel)); err != nil {
		logrus.WithError(err).Error("Failed to send slack message")
	}
	logrus.WithFields(logrus.Fields{
		"name": name,
		"URL":  hashrel.URL(),
	}).Info("Published hashrelease")
}

// HashreleaseCleanRemote cleans up old hashreleases on the docs host
func HashreleaseCleanRemote(cfg *config.Config) {
	logrus.Info("Cleaning up old hashreleases")
	if err := hashreleaseserver.CleanOldHashreleases(&cfg.HashreleaseServerConfig); err != nil {
		logrus.WithError(err).Fatal("Failed to delete old hashreleases")
	}
}

// ReformatHashrelease modifies the generated release output to match
// the "legacy" format our CI tooling expects. This should be temporary until
// we can update the tooling to expect the new format.
// Specifically, we need to do two things:
// - Copy the windows zip file to files/windows/calico-windows-<ver>.zip
// - Copy tigera-operator-<ver>.tgz to tigera-operator.tgz
func ReformatHashrelease(cfg *config.Config, dir string) error {
	logrus.Info("Modifying hashrelease output to match legacy format")
	pinned, err := pinnedversion.RetrievePinnedVersion(cfg.TmpFolderPath())
	if err != nil {
		return err
	}
	ver := pinned.Components["calico"].Version

	// Copy the windows zip file to files/windows/calico-windows-<ver>.zip
	if err := os.MkdirAll(filepath.Join(dir, "files", "windows"), 0o755); err != nil {
		return err
	}
	windowsZip := filepath.Join(dir, fmt.Sprintf("calico-windows-%s.zip", ver))
	windowsZipDst := filepath.Join(dir, "files", "windows", fmt.Sprintf("calico-windows-%s.zip", ver))
	if err := utils.CopyFile(windowsZip, windowsZipDst); err != nil {
		return err
	}

	// Copy the ocp.tgz to manifests/ocp.tgz
	ocpTarball := filepath.Join(dir, "ocp.tgz")
	ocpTarballDst := filepath.Join(dir, "manifests", "ocp.tgz")
	if err := utils.CopyFile(ocpTarball, ocpTarballDst); err != nil {
		return err
	}

	// Copy the operator tarball to tigera-operator.tgz
	helmChartVersion := ver
	operatorTarball := filepath.Join(dir, fmt.Sprintf("tigera-operator-%s.tgz", helmChartVersion))
	operatorTarballDst := filepath.Join(dir, "tigera-operator.tgz")
	if err := utils.CopyFile(operatorTarball, operatorTarballDst); err != nil {
		return err
	}
	return nil
}
