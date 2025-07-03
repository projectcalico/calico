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

package hashreleaseserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
)

const (
	// DefaultMax is the number of hashreleases to keep in the server
	DefaultMax = 400

	// BaseDomain is the base URL of the hashrelease
	BaseDomain = "docs.eng.tigera.net"

	releaseLibFileName = "all-releases"
)

type Hashrelease struct {
	// Name is the name of the hashrelease.
	// When publishing a hashrelease, this is the name of the folder in the server.
	// When getting a hashrelease, this is the full path of the hashrelease folder.
	Name string

	// Hash is the hash of the hashrelease
	Hash string

	// Note is the info about the hashrelease
	Note string

	// Stream is the version the hashrelease is for (e.g master, v3.19)
	Stream string

	// ProductVersion is the product version in the hashrelease
	ProductVersion string

	// OperatorVersion is the operator version for the hashreleaseq
	OperatorVersion string

	// Source is the source of hashrelease content
	Source string

	// Time is the modified time of the hashrelease
	Time time.Time

	// Latest is if the hashrelease is the latest for the stream
	Latest bool

	ImageScanResultURL string
}

func (h *Hashrelease) URL() string {
	return fmt.Sprintf("https://%s.%s", h.Name, BaseDomain)
}

// PublishHashrelease publishes the hashrelease in 3 parts
//
// 1. It publishes the hashrelease to the server via SSH and to cloud storage.
//
// 2. It adds the hashrelease to the hashrelease library on the server and cloud storage.
//
// 3. It sets it as the latest for its product stream if specified.
func Publish(productCode string, h *Hashrelease, cfg *Config) error {
	srcDir := strings.TrimSuffix(h.Source, "/") + "/"
	logrus.WithFields(logrus.Fields{
		"hashrelease": h.Name,
		"srcDir":      srcDir,
		"latest":      h.Latest,
	}).Info("Publishing hashrelease")

	if err := publishFiles(h, cfg); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease")
		return fmt.Errorf("failed to publish hashrelease %s: %w", h.Name, err)
	}

	// add the hashrelease to the library
	if err := addToHashreleaseLibrary(*h, cfg); err != nil {
		logrus.WithError(err).Error("failed to add hashrelease to library")
		return err
	}

	if h.Latest {
		if err := setHashreleaseAsLatest(*h, productCode, cfg); err != nil {
			// We don't want to fail the publish if we can't set it as latest, but we should log the error
			logrus.WithError(err).Error("failed to set hashrelease as latest")
		}
	}

	return nil
}

func publishFiles(h *Hashrelease, cfg *Config) error {
	logrus.WithFields(logrus.Fields{
		"hashrelease": h.Name,
		"srcDir":      h.Source,
	}).Info("Publishing hashrelease")
	var allErr error
	// publish to the server via SSH
	logrus.WithField("hashrelease", h.Name).Debug("Publishing hashrelease via SSH")
	if _, err := command.Run("rsync",
		[]string{
			"--stats", "-az", "--delete",
			fmt.Sprintf("--rsh=%s", cfg.RSHCommand()), h.Source,
			fmt.Sprintf("%s:%s/%s", cfg.HostString(), RemoteDocsPath(cfg.User), h.Name),
		}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease via SSH")
		allErr = errors.Join(allErr, fmt.Errorf("failed to publish hashrelease %s via SSH: %w", h.Name, err))
	}
	// publish to cloud storage
	account, err := cfg.credentialsAccount()
	if err != nil {
		logrus.WithError(err).Error("Failed to get credentials email for hashrelease server")
		return errors.Join(allErr, fmt.Errorf("failed to get credentials email for hashrelease server: %w", err))
	}
	logrus.WithField("hashrelease", h.Name).Debug("Publishing hashrelease to cloud storage")
	args := []string{
		"storage", "rsync",
		h.Source, fmt.Sprintf("gs://%s/%s", cfg.BucketName, h.Name),
		"--recursive", "--delete-unmatched-destination-objects",
		fmt.Sprintf("--account=%s", account),
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbosity=debug")
	}
	if _, err := command.Run("gcloud", args); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease to bucket")
		return errors.Join(allErr, fmt.Errorf("failed to publish hashrelease %s to bucket: %w", h.Name, err))
	}
	logrus.WithField("hashrelease", h.Name).Debug("Published hashrelease without error")
	return nil
}

func RemoteDocsPath(user string) string {
	path := "files"
	if user != "root" {
		path = filepath.Join("home", "core", "disk", "docs-preview", path)
	}
	return "/" + path
}

func remoteReleasesLibraryPath(user string) string {
	return filepath.Join(RemoteDocsPath(user), releaseLibFileName)
}

func HasHashrelease(hash string, cfg *Config) (bool, error) {
	logrus.WithField("hash", hash).Debug("Checking if hashrelease exists")
	out, err := runSSHCommand(cfg, fmt.Sprintf("cat %s | grep %s", remoteReleasesLibraryPath(cfg.User), hash))
	if err != nil {
		if strings.Contains(err.Error(), "exited with status 1") {
			// Process exited with status 1 is from grep when no match is found
			logrus.WithError(err).Error("Hashrelease not found")
			return false, nil
		} else {
			// Some other error occurred, log it and check the bucket hashrelease library
			logrus.WithError(err).Error("Failed to check hashrelease on server, checking bucket instead")
			bucket, err := cfg.Bucket()
			if err != nil {
				logrus.WithError(err).Error("Failed to get bucket handler for hashrelease server")
				return false, fmt.Errorf("failed to get bucket handler for hashrelease server: %w", err)
			}
			reader, err := bucket.Object(releaseLibFileName).NewReader(context.Background())
			if err != nil {
				if errors.Is(err, storage.ErrObjectNotExist) {
					logrus.Debug("Hashrelease library does not exist")
					return false, nil // No hashreleases published yet
				}
				logrus.WithError(err).Error("Failed to read hashrelease library from bucket")
				return false, fmt.Errorf("failed to read hashrelease library from bucket: %w", err)
			}
			defer reader.Close()
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, hash) {
					logrus.WithField("hash", hash).Debug("Found hashrelease in library")
					return true, nil
				}
			}
			if err := scanner.Err(); err != nil {
				logrus.WithError(err).Error("Failed to scan hashrelease library")
				return false, fmt.Errorf("failed to scan hashrelease library: %w", err)
			}
			return false, nil
		}
	}
	return strings.Contains(out, hash), nil
}

// setHashreleaseAsLatest sets the hashrelease as the latest for the stream
func setHashreleaseAsLatest(rel Hashrelease, productCode string, cfg *Config) error {
	logrus.WithFields(logrus.Fields{
		"hashrelease": rel.Name,
		"stream":      rel.Stream,
		"productCode": productCode,
	}).Info("Setting hashrelease as latest for stream")
	var allErr error
	content := rel.URL() + "/"
	relFilePath := filepath.Join("latest-"+productCode, rel.Stream+".txt")
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s" > %s`, content, filepath.Join(RemoteDocsPath(cfg.User), relFilePath))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease via SSH")
		allErr = errors.Join(allErr, err)
	}
	// Try to write to the latest hashrelease file in the bucket
	bucket, err := cfg.Bucket()
	if err != nil {
		logrus.WithError(err).Error("Failed to get bucket handler for hashrelease server")
		return errors.Join(allErr, fmt.Errorf("failed to get bucket handler for hashrelease server: %w", err))
	}
	if err := updateBucketTextFile(bucket, relFilePath, content, false); err != nil {
		logrus.WithError(err).Errorf("Failed to write to latest hashrelease file for %s %s in bucket", productCode, rel.Stream)
		return errors.Join(allErr, fmt.Errorf("failed to update latest hashrelease file in bucket: %w", err))
	}
	return nil
}

func addToHashreleaseLibrary(rel Hashrelease, cfg *Config) error {
	logrus.WithField("hashrelease", rel.Name).WithField("hash", rel.Hash).Info("Adding hashrelease to library")
	var allErr error
	content := fmt.Sprintf("%s - %s ", rel.Hash, rel.Note)
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s" >> %s`, content, remoteReleasesLibraryPath(cfg.User))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		allErr = errors.Join(allErr, fmt.Errorf("failed to update hashrelease library via SSH: %w", err))
	}
	// Try to write to the hashrelease library in the bucket
	bucket, err := cfg.Bucket()
	if err != nil {
		// For now if we can't get the bucket, do not fail the operation
		logrus.WithError(err).Error("Failed to get bucket for hashrelease server")
		return errors.Join(allErr, fmt.Errorf("failed to get bucket for hashrelease server: %w", err))
	}
	if err := updateBucketTextFile(bucket, releaseLibFileName, content, true); err != nil {
		logrus.WithError(err).Error("Failed to write to hashrelease library in bucket")
		return errors.Join(allErr, fmt.Errorf("failed to update hashrelease library in bucket: %w", err))
	}
	return nil
}

func updateBucketTextFile(bucket *storage.BucketHandle, filePath, content string, appendContent bool) error {
	ctx := context.Background()
	obj := bucket.Object(filePath)
	w := obj.NewWriter(ctx)
	w.ContentType = "text/plain"
	w.Metadata = map[string]string{
		"updated-by": "hashreleaseserver",
		"updated-at": time.Now().Format(time.RFC3339),
	}
	defer func() {
		if err := w.Close(); err != nil {
			logrus.WithError(err).Errorf("Failed to close writer for bucket: %s", filePath)
		}
	}()
	// If the file already exists and we are not appending, we will overwrite it
	updatedContent := content
	if appendContent {
		// If we are appending, we need to read the existing content first
		existingReader, err := obj.NewReader(ctx)
		if err != nil {
			if !errors.Is(err, storage.ErrObjectNotExist) {
				logrus.WithError(err).Errorf("Failed to read existing content from bucket: %s", filePath)
				return fmt.Errorf("failed to read existing content from bucket %s: %w", filePath, err)
			}
		} else {
			defer existingReader.Close()
			existingContent, err := io.ReadAll(existingReader)
			if err != nil {
				logrus.WithError(err).Errorf("Failed to read existing content from bucket: %s", filePath)
				return fmt.Errorf("failed to read existing content from bucket %s: %w", filePath, err)
			}
			updatedContent = strings.TrimRight(string(existingContent), "\n") + "\n" + content + "\n"
		}
	}
	if _, err := w.Write([]byte(updatedContent)); err != nil {
		logrus.WithError(err).Errorf("Failed to write content to bucket: %s", filePath)
		return fmt.Errorf("failed to write content to bucket %s: %w", filePath, err)
	}
	return nil
}

func CleanOldHashreleases(cfg *Config, maxToKeep int) error {
	folders, err := listHashreleases(cfg)
	if err != nil {
		logrus.WithError(err).Error("Failed to list hashreleases")
		return err
	}
	foldersToDelete := []string{}
	if len(folders) > maxToKeep {
		for i := 0; i < len(folders)-maxToKeep; i++ {
			foldersToDelete = append(foldersToDelete, folders[i].Name)
		}
	}
	if len(foldersToDelete) == 0 {
		logrus.Info("No hashreleases to delete")
		return nil
	}
	if _, err := runSSHCommand(cfg, fmt.Sprintf("rm -rf %s", strings.Join(foldersToDelete, " "))); err != nil {
		logrus.WithField("folder", strings.Join(foldersToDelete, ", ")).WithError(err).Error("Failed to delete old hashrelease")
		return err
	}
	logrus.WithField("folders", strings.Join(foldersToDelete, ", ")).Info("Deleted old hashreleases")
	if err := cleanHashreleaseLibrary(cfg, foldersToDelete); err != nil {
		logrus.WithError(err).Warn("Failed to clean hashrelease library")
	}
	return nil
}

func listHashreleases(cfg *Config) ([]Hashrelease, error) {
	cmd := fmt.Sprintf("ls -lt --time-style=+'%%Y-%%m-%%d %%H:%%M:%%S' %s", RemoteDocsPath(cfg.User))
	out, err := runSSHCommand(cfg, cmd)
	if err != nil {
		logrus.WithError(err).Error("Failed to get list of hashreleases")
		return nil, err
	}
	lines := strings.Split(out, "\n")
	var releases []Hashrelease
	// Limit to folders name which have the format YYYY-MM-DD-vX.Y-<word>
	re := regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}-v[0-9]+\.[0-9]+-.*$`)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Get the last field which is the folder name
		name := fields[len(fields)-1]
		time, err := time.Parse("2006-01-02 15:04:05", fmt.Sprintf("%s %s", fields[5], fields[6]))
		if err != nil {
			continue
		}
		if re.MatchString(name) {
			releases = append(releases, Hashrelease{
				Name: filepath.Join(RemoteDocsPath(cfg.User), name),
				Time: time,
			})
		}
		sort.Slice(releases, func(i, j int) bool {
			return releases[i].Time.Before(releases[j].Time)
		})
	}
	return releases, nil
}

func getHashreleaseLibrary(cfg *Config) (string, error) {
	out, err := runSSHCommand(cfg, fmt.Sprintf("cat %s", remoteReleasesLibraryPath(cfg.User)))
	if err != nil {
		logrus.WithError(err).Error("Failed to get hashrelease library")
		return "", err
	}
	return out, nil
}

func cleanHashreleaseLibrary(cfg *Config, hashreleaseNames []string) error {
	library, err := getHashreleaseLibrary(cfg)
	if err != nil {
		return err
	}
	scanner := bufio.NewScanner(strings.NewReader(library))
	var newLibrary []string
	for scanner.Scan() {
		line := scanner.Text()
		for _, name := range hashreleaseNames {
			if !strings.Contains(line, name) {
				newLibrary = append(newLibrary, line)
			}
		}
	}

	if _, err := runSSHCommand(cfg, fmt.Sprintf("echo \"%s\" > %s", strings.Join(newLibrary, "\n"), remoteReleasesLibraryPath(cfg.User))); err != nil {
		logrus.WithError(err).Error("Failed to update hashrelease library")
		return err
	}
	return nil
}
