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
	_ "embed"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultMax is the number of hashreleases to keep in the server
	DefaultMax = 400

	// BaseDomain is the base URL of the hashrelease
	BaseDomain = "docs.eng.tigera.net"
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

func RemoteDocsPath(user string) string {
	path := "files"
	if user != "root" {
		path = filepath.Join("home", "core", "disk", "docs-preview", path)
	}
	return "/" + path
}

func remoteReleasesLibraryPath(user string) string {
	return filepath.Join(RemoteDocsPath(user), "all-releases")
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
	logrus.Debugf("Updating latest hashrelease for %s stream to %s", rel.Stream, rel.Name)
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s/" > %s/latest-%s/%s.txt`, rel.URL(), RemoteDocsPath(cfg.User), productCode, rel.Stream)); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		return err
	}
	return nil
}

func AddToHashreleaseLibrary(rel Hashrelease, cfg *Config) error {
	logrus.WithField("hashrelease", rel.Name).WithField("hash", rel.Hash).Debug("Adding hashrelease to library")
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s - %s " >> %s`, rel.Hash, rel.Note, remoteReleasesLibraryPath(cfg.User))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
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
