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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

	// Dest is the path to the hashrelease dir on the server
	Dest string

	// Time is the modified time of the hashrelease
	Time time.Time

	// Latest is if the hashrelease is the latest for the stream
	Latest bool

	ImageScanResultURL string
}

func (h *Hashrelease) URL() string {
	return fmt.Sprintf("https://%s.%s", h.Name, BaseDomain)
}

// PublishHashrelease uploads the hashrelease to the server.
func Publish(h *Hashrelease, cfg *Config) error {
	srcDir := strings.TrimSuffix(h.Source, "/") + "/"
	logrus.WithFields(logrus.Fields{
		"hashrelease": h.Name,
		"srcDir":      srcDir,
	}).Info("Publishing hashrelease")

	var publishErr error
	// publish to hashrelease server VM
	if _, err := command.Run("rsync",
		[]string{
			"--stats", "-az", "--delete",
			fmt.Sprintf("--rsh=%s", cfg.RSHCommand()), srcDir,
			fmt.Sprintf("%s:%s/%s", cfg.HostString(), RemoteDocsPath(cfg.User), h.Name),
		}); err != nil {
		logrus.WithError(err).Error("Failed to publish hashrelease to hashrelease server VM")
		publishErr = err
	}
	// publish to cloud storage
	if err := command.GcloudStorageRsync(
		srcDir,
		fmt.Sprintf("gcs://%s/%s", cfg.BucketName, h.Name),
		"--delete-unmatched-destination-objects",
	); err != nil {
		// If publishing to cloud storage fails, we only log the error
		// as it is currently not critical to the operation of the hashrelease server.
		logrus.WithError(err).Error("Failed to publish hashrelease to cloud storage")
	}
	if publishErr != nil {
		return fmt.Errorf("failed to publish hashrelease %s: %w", h.Name, publishErr)
	}

	// add the hashrelease to the library
	if err := AddToHashreleaseLibrary(*h, cfg); err != nil {
		logrus.WithError(err).Error("Failed to add hashrelease to library")
		return err
	}

	// set the hashrelease as the latest for the stream
	if err := SetHashreleaseAsLatest(*h, h.Stream, cfg); err != nil {
		// We don't want to fail the publish if we can't set it as latest, but we should log the error
		logrus.WithError(err).Error("Failed to set hashrelease as latest")
	}

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
			logrus.WithError(err).Info("Hashrelease does not already exist on server")
			return false, nil
		} else {
			logrus.WithError(err).Error("Failed to check hashrelease library")
			return false, err
		}
	}
	return strings.Contains(out, hash), nil
}

// SetHashreleaseAsLatest sets the hashrelease as the latest for the stream
func SetHashreleaseAsLatest(rel Hashrelease, productCode string, cfg *Config) error {
	logrus.WithFields(logrus.Fields{
		"hashrelease": rel.Name,
		"stream":      rel.Stream,
		"productCode": productCode,
	}).Debug("Setting hashrelease as latest for stream")
	var allErr error
	content := rel.URL() + "/"
	relFilePath := fmt.Sprintf("latest-%s/%s.txt", productCode, rel.Stream)
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s" > %s/%s`, content, RemoteDocsPath(cfg.User), relFilePath)); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		allErr = errors.Join(allErr, err)
	}
	// Try to write to the latest hashrelease file in the bucket
	// For now we do not fail the operation if we can't write to the bucket
	// as it is currently not critical to the operation of the hashrelease server
	bucket, err := cfg.Bucket()
	if err != nil {
		// For now if we can't get the bucket, do not fail the operation
		logrus.WithError(err).Error("Failed to get bucket for hashrelease server")
		return allErr
	}
	if err := updateBucketTextFile(bucket, relFilePath, content, false); err != nil {
		logrus.WithError(err).Errorf("Failed to write to latest hashrelease file for %s %s in bucket", productCode, rel.Stream)
	}
	return nil
}

func AddToHashreleaseLibrary(rel Hashrelease, cfg *Config) error {
	logrus.WithField("hashrelease", rel.Name).WithField("hash", rel.Hash).Debug("Adding hashrelease to library")
	var allErr error
	content := fmt.Sprintf("%s - %s ", rel.Hash, rel.Note)
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s" >> %s`, content, remoteReleasesLibraryPath(cfg.User))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		allErr = errors.Join(allErr, err)
	}
	// Try to write to the hashrelease library in the bucket
	// For now we do not fail the operation if we can't write to the bucket
	// as it is currently not critical to the operation of the hashrelease server
	// and there is a job that runs periodically sync files from the VM to the bucket
	bucket, err := cfg.Bucket()
	if err != nil {
		// For now if we can't get the bucket, do not fail the operation
		logrus.WithError(err).Error("Failed to get bucket for hashrelease server")
		return allErr
	}
	if err := updateBucketTextFile(bucket, releaseLibFileName, content, true); err != nil {
		logrus.WithError(err).Error("Failed to write to hashrelease library in bucket")
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
	// If the file already exists and we are not appending, we will overwrite it
	updatedContent := content
	if appendContent {
		// If we are appending, we need to read the existing content first
		existingReader, err := obj.NewReader(ctx)
		if err != nil {
			if !errors.Is(err, storage.ErrObjectNotExist) {
				logrus.WithError(err).Errorf("Failed to read existing content from bucket: %s", filePath)
				return err
			}
		} else {
			defer existingReader.Close()
			existingContent, err := io.ReadAll(existingReader)
			if err != nil {
				logrus.WithError(err).Errorf("Failed to read existing content from bucket: %s", filePath)
				return err
			}
			updatedContent = strings.TrimRight(string(existingContent), "\n") + "\n" + content + "\n"
		}
	}
	if _, err := w.Write([]byte(updatedContent)); err != nil {
		logrus.WithError(err).Errorf("Failed to write content to bucket: %s", filePath)
		return err
	}
	if err := w.Close(); err != nil {
		logrus.WithError(err).Errorf("Failed to close writer for bucket: %s", filePath)
		return err
	}
	return nil
}

func CleanOldHashreleases(cfg *Config, maxToKeep int) error {
	logrus.WithField("maxToKeep", maxToKeep).Info("Cleaning old hashreleases")
	folders, err := listHashreleases(cfg)
	if err != nil {
		logrus.WithError(err).Error("Failed to list hashreleases")
		return err
	}
	foldersToDelete := []string{}
	hashreleaseToDeleteFromLibrary := []string{}
	if len(folders) > maxToKeep {
		for i := 0; i < len(folders)-maxToKeep; i++ {
			foldersToDelete = append(foldersToDelete, folders[i].Dest)
			hashreleaseToDeleteFromLibrary = append(hashreleaseToDeleteFromLibrary, folders[i].Name)
		}
	}
	if len(foldersToDelete) == 0 {
		logrus.Infof("There are %d hashreleases which is less than maxToKeep %d", len(folders), maxToKeep)
		return nil
	}
	if _, err := runSSHCommand(cfg, fmt.Sprintf("rm -rf %s", strings.Join(foldersToDelete, " "))); err != nil {
		logrus.WithField("folders", strings.Join(foldersToDelete, ", ")).WithError(err).Error("Failed to delete old hashreleases")
		return err
	}
	logrus.Infof("Deleted %d old hashreleases", len(foldersToDelete))
	logrus.WithField("folders", strings.Join(foldersToDelete, ", ")).Debug("Deleted hashreleases")
	if err := cleanHashreleaseLibrary(cfg, hashreleaseToDeleteFromLibrary); err != nil {
		logrus.WithError(err).Warn("Failed to clean hashrelease library")
	}
	return nil
}

func listHashreleases(cfg *Config) ([]Hashrelease, error) {
	remoteDocsPath := RemoteDocsPath(cfg.User)
	// retrieve the list of folders in the hashrelease directory
	// and get the last modified time as seconds since Epoch of each folder
	// the command should return in the format:
	// RemoteDocsPath(cfg.User) + "/YYYY-MM-DD-vX.Y-<word> <time>"
	// e.g.
	// /files/2024-12-20-v3-20-reckless 1734714011
	// /files/2025-03-09-v3-21-1-sinner 1741499249
	cmd := fmt.Sprintf(`find %s -maxdepth 1 -type d `+
		`-exec bash -c 'echo $1 $(stat -c %%Y $1)' -- '{}' \;`, remoteDocsPath)
	out, err := runSSHCommand(cfg, cmd)
	if err != nil {
		logrus.WithError(err).Error("Failed to get list of hashreleases")
		return nil, err
	}
	lines := strings.Split(out, "\n")
	logrus.Debugf("hashrelease server returned %d folders in %s", len(lines), remoteDocsPath)
	var releases []Hashrelease
	// Ensure it is only folders name which have the format YYYY-MM-DD-vX.Y-<word>
	re := regexp.MustCompile(fmt.Sprintf(`^%s/[0-9]{4}-[0-9]{2}-[0-9]{2}-.+$`, remoteDocsPath))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(line, " ")
		name := fields[0]
		parsedTime, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			logrus.WithError(err).Errorf("Failed to parse time from field: %s", fields[1])
			continue
		}
		time := time.Unix(parsedTime, 0)
		if re.MatchString(name) {
			releases = append(releases, Hashrelease{
				Name: strings.TrimPrefix(name, remoteDocsPath+"/"),
				Time: time,
				Dest: name,
			})
		}
	}
	sort.Slice(releases, func(i, j int) bool {
		return releases[i].Time.Before(releases[j].Time)
	})
	logrus.Debugf("Found %d hashreleases", len(releases))
	return releases, nil
}

func getHashreleaseLibrary(cfg *Config) ([]string, error) {
	out, err := runSSHCommand(cfg, fmt.Sprintf("cat %s", remoteReleasesLibraryPath(cfg.User)))
	if err != nil {
		logrus.WithError(err).Error("Failed to get hashrelease library")
		return nil, err
	}
	return strings.Split(out, "\n"), nil
}

func cleanHashreleaseLibrary(cfg *Config, hashreleaseNames []string) error {
	logrus.WithField("path", remoteReleasesLibraryPath(cfg.User)).Info("Updating hashrelease library")
	library, err := getHashreleaseLibrary(cfg)
	if err != nil {
		return err
	}
	logrus.Debugf("Hashrelease library currently has %d entries", len(library))
	newLibrary := []string{}
	for _, entry := range library {
		found := false
		for _, name := range hashreleaseNames {
			if strings.Contains(entry, name) {
				found = true
				break
			}
		}
		if !found {
			newLibrary = append(newLibrary, entry)
		}
	}
	logrus.Debugf("Hashrelease library will have %d entries after cleaning", len(newLibrary))
	if _, err := runSSHCommandWithStdin(cfg, fmt.Sprintf("cat > %s", remoteReleasesLibraryPath(cfg.User)), bytes.NewBufferString(strings.Join(newLibrary, "\n"))); err != nil {
		logrus.WithError(err).Error("Failed to update hashrelease library")
		return err
	}
	return nil
}
