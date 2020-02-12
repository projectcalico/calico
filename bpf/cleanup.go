// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package bpf

import (
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func CleanUpCalicoPins(dir string) {
	// Look for pinned maps and remove them.
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(info.Name(), "cali_") || strings.HasPrefix(info.Name(), "calico_") {
			log.WithField("path", path).Debug("Deleting pinned BPF resource")
			err = os.Remove(path)
			if err != nil {
				log.WithError(err).Info("Failed to remove pin, ignoring.")
			}
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		log.WithError(err).Warn("Failed to remove pinned BPF progs/maps. Ignoring.")
	}
}
