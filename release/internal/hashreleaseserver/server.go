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
	_ "embed"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
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
			logrus.WithError(err).Error("Hashrelease not found")
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
	if _, err := runSSHCommand(cfg, fmt.Sprintf(`echo "%s/" > %s/latest-%s/%s.txt && echo %s >> %s`, rel.URL(), RemoteDocsPath(cfg.User), productCode, rel.Stream, rel.Name, remoteReleasesLibraryPath(cfg.User))); err != nil {
		logrus.WithError(err).Error("Failed to update latest hashrelease and hashrelease library")
		return err
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
