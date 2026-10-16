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

const (
	sizeFileV4 = "bpf_ct4_map_size"
	sizeFileV6 = "bpf_ct6_map_size"
	// Read by older Felix for both families; kept at the larger size so a downgrade never shrinks a map.
	sizeFileShared = "bpf_ct_map_size"
)

func sizeFile(ipVersion int) string {
	if ipVersion == 6 {
		return sizeFileV6
	}
	return sizeFileV4
}

// GrownMapSizes returns the IPv4 and IPv6 conntrack map sizes recorded by
// autoscaling, 0 for a family that never grew.
func GrownMapSizes() (v4, v6 int, err error) {
	if v4, err = readMapSizeFile(sizeFileV4); err != nil {
		return 0, 0, err
	}
	if v6, err = readMapSizeFile(sizeFileV6); err != nil {
		return 0, 0, err
	}
	shared, err := readMapSizeFile(sizeFileShared)
	if err != nil {
		return 0, 0, err
	}
	if shared <= max(v4, v6) {
		return v4, v6, nil
	}

	// Only an older Felix grows the shared file past both; it sized both families from it.
	for _, f := range []string{sizeFileV4, sizeFileV6} {
		if err := writeMapSizeFile(f, shared); err != nil {
			log.WithError(err).Warn("Failed to record the conntrack map size.")
		}
	}
	return shared, shared, nil
}

// recordGrowth records a family's new map size, keeping the shared file at the
// larger of the family sizes.
func recordGrowth(ipVersion, size int) error {
	if err := writeMapSizeFile(sizeFile(ipVersion), size); err != nil {
		return err
	}
	shared, err := readMapSizeFile(sizeFileShared)
	if err != nil || shared < size {
		return writeMapSizeFile(sizeFileShared, size)
	}
	return nil
}

func readMapSizeFile(name string) (int, error) {
	data, err := os.ReadFile(filepath.Join(MapSizeDir, name))
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func writeMapSizeFile(name string, size int) error {
	if err := os.MkdirAll(MapSizeDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", MapSizeDir, err)
	}

	filename := filepath.Join(MapSizeDir, name)
	log.Debugf("Writing %d to %s", size, filename)
	if err := os.WriteFile(filename, fmt.Appendf(nil, "%d", size), 0o644); err != nil {
		return fmt.Errorf("unable to write to %s: %w", filename, err)
	}
	return nil
}
