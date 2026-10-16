// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package conntrack

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// MapSizeDir holds the files that record conntrack map growth across Felix restarts.
var MapSizeDir = "/var/lib/calico"

func mapSizeFile(ipVersion int) string {
	if ipVersion == 6 {
		return filepath.Join(MapSizeDir, "bpf_ct6_map_size")
	}
	return filepath.Join(MapSizeDir, "bpf_ct_map_size")
}

// MapSizeFromFile returns the grown conntrack map size recorded for the IP
// family, or 0 if the map has not grown.
func MapSizeFromFile(ipVersion int) (int, error) {
	size, err := readMapSizeFile(mapSizeFile(ipVersion))
	if err != nil || size != 0 || ipVersion != 6 {
		return size, err
	}

	// Older Felix sized both families from the v4 file; copy it so v6 neither
	// shrinks nor follows v4.
	size, err = readMapSizeFile(mapSizeFile(4))
	if err != nil || size == 0 {
		return size, err
	}
	if err := writeMapSizeFile(6, size); err != nil {
		log.WithError(err).Warn("Failed to record the IPv6 conntrack map size.")
	}
	return size, nil
}

func readMapSizeFile(filename string) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func writeMapSizeFile(ipVersion, size int) error {
	if err := os.MkdirAll(MapSizeDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", MapSizeDir, err)
	}

	filename := mapSizeFile(ipVersion)
	log.Debugf("Writing %d to %s", size, filename)
	if err := os.WriteFile(filename, fmt.Appendf(nil, "%d", size), 0o644); err != nil {
		return fmt.Errorf("unable to write to %s: %w", filename, err)
	}
	return nil
}
