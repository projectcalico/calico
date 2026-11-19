// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package outputs

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/fsutil"
)

const (
	SumsFileName = "SHA256SUMS"

	ChecksumStep = "checksums"
)

// SHA256Sums replaces dir's sums file, covering the files the filters pick.
// Names stay relative to dir, so it verifies wherever the assets land.
func SHA256Sums(r command.CommandRunner, dir string, filters ...fsutil.FileFilter) error {
	path := filepath.Join(dir, SumsFileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	files, err := fsutil.ListFiles(dir, append(slices.Clone(filters), fsutil.Exclude(SumsFileName))...)
	if err != nil {
		return fmt.Errorf("listing files to checksum: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no files to checksum in %s", dir)
	}
	names := make([]string, len(files))
	for idx, file := range files {
		names[idx] = filepath.Base(file)
	}
	out, err := command.Runner(r).Run("sha256sum", names, command.WithDir(dir))
	if err != nil {
		return fmt.Errorf("checksumming files: %w", err)
	}
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	logrus.WithField("files", len(files)).Info("Wrote checksums")
	return nil
}
