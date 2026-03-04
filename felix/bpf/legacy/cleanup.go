//go:build !windows

// Copyright (c) 2023 Tigera, Inc. All rights reserved.
//
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

package legacy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/set"
)

const jumpMapVersion = 3

func JumpMapName() string {
	return fmt.Sprintf("cali_jump%d", jumpMapVersion)
}

const countersMapVersion = 1

func CountersMapName() string {
	return fmt.Sprintf("cali_counters%d", countersMapVersion)
}

func ListPerEPMaps() (map[int]string, error) {
	mapIDToPath := make(map[int]string)
	err := filepath.Walk("/sys/fs/bpf/tc", /* N.B. hardcoded to what it used to be! */
		func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.Contains(p, "globals") {
				return nil
			}
			if strings.HasPrefix(info.Name(), JumpMapName()) ||
				strings.HasPrefix(info.Name(), CountersMapName()) {
				log.WithField("path", p).Debug("Examining map")

				out, err := exec.Command("bpftool", "map", "show", "pinned", p).Output()
				if err != nil {
					log.WithError(err).Panic("Failed to show map")
				}
				log.WithField("dump", string(out)).Debug("Map show before deletion")
				idStr := string(bytes.Split(out, []byte(":"))[0])
				id, err := strconv.Atoi(idStr)
				if err != nil {
					log.WithError(err).WithField("dump", string(out)).Error("Failed to parse bpftool output.")
					return err
				}
				mapIDToPath[id] = p
			}
			return nil
		})

	return mapIDToPath, err
}

// pinDirRegex matches tc's and xdp's auto-created directory names, directories created when using libbpf
// so we can clean them up when removing maps without accidentally removing other user-created dirs..
var pinDirRegex = regexp.MustCompile(`([0-9a-f]{40})|(.*_(igr|egr|xdp))`)

// CleanUpMaps scans for cali_jump maps that are still pinned to the filesystem but no longer referenced by
// our BPF programs.
func CleanUpMaps() {
	// Find the maps we care about by walking the BPF filesystem.
	mapIDToPath, err := ListPerEPMaps()
	if os.IsNotExist(err) {
		log.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		log.WithError(err).Error("Error while looking for maps.")
		return
	}

	// Remove the pins.
	for id, p := range mapIDToPath {
		log.WithFields(log.Fields{"id": id, "path": p}).Debug("Removing stale BPF map pin.")
		err := os.Remove(p)
		if err != nil {
			log.WithError(err).Warn("Removed stale BPF map pin.")
		}
		log.WithFields(log.Fields{"id": id, "path": p}).Info("Removed stale BPF map pin.")
	}

	// Look for empty dirs.
	emptyAutoDirs := set.New[string]()
	err = filepath.Walk("/sys/fs/bpf/tc", func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && pinDirRegex.MatchString(info.Name()) {
			p := path.Clean(p)
			log.WithField("path", p).Debug("Found tc auto-created dir.")
			emptyAutoDirs.Add(p)
		} else {
			dirPath := path.Clean(path.Dir(p))
			if emptyAutoDirs.Contains(dirPath) {
				log.WithField("path", dirPath).Debug("tc dir is not empty.")
				emptyAutoDirs.Discard(dirPath)
			}
		}
		return nil
	})
	if os.IsNotExist(err) {
		log.WithError(err).Warn("tc directory missing from BPF file system?")
		return
	}
	if err != nil {
		log.WithError(err).Error("Error while looking for maps.")
	}

	for p := range emptyAutoDirs.All() {
		log.WithField("path", p).Debug("Removing empty dir.")
		err := os.Remove(p)
		if err != nil {
			log.WithError(err).Error("Error while removing empty dir.")
		}
	}
}
