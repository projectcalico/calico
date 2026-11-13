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

package binaries

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	e2eConfigDir = "config"

	// e2eConfigArchive is the file name, under E2EDir, that scheduled lanes
	// download. The object store has no directory listing, so the tree ships as
	// one archive whose paths all start with "config/".
	e2eConfigArchive = e2eConfigDir + ".tar.gz"
)

// E2EConfigPath returns where the e2e config archive lives under outputDir.
func E2EConfigPath(outputDir string) string {
	return filepath.Join(E2EDir(outputDir), e2eConfigArchive)
}

// PackageE2EConfig archives the repository's e2e/config tree into the e2e
// directory of outputDir, next to the e2e binaries built from the same commit.
// Relative paths are kept exactly, because configs name nested paths and
// extend relative parents. An absent or empty tree is an error, so a release
// never publishes binaries whose configs are missing.
func PackageE2EConfig(repoRoot, outputDir string) error {
	if repoRoot == "" || outputDir == "" {
		return errors.New("packaging e2e config: repository root and output directory are required")
	}
	src := filepath.Join(repoRoot, E2EComponent, e2eConfigDir)
	files, err := regularFiles(src)
	if err != nil {
		return fmt.Errorf("reading e2e config %s: %w", src, err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no e2e config files found in %s", src)
	}
	if err := os.MkdirAll(E2EDir(outputDir), utils.DirPerms); err != nil {
		return fmt.Errorf("creating %s: %w", E2EDir(outputDir), err)
	}
	dest := E2EConfigPath(outputDir)
	if err := writeArchive(dest, src, files); err != nil {
		if rmErr := os.Remove(dest); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			logrus.WithError(rmErr).WithField("path", dest).Warn("Could not remove partial e2e config archive")
		}
		return fmt.Errorf("writing %s: %w", dest, err)
	}
	return nil
}

// regularFiles lists the regular files under dir as slash-separated relative
// paths in sorted order, so the archive is the same for the same tree. Any
// other entry, such as a symlink, is an error rather than a file silently
// missing from the archive.
func regularFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	slices.Sort(out)
	return out, err
}

func writeArchive(dest, src string, files []string) error {
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	var writeErr error
	for _, rel := range files {
		if writeErr = addFile(tw, src, rel); writeErr != nil {
			break
		}
	}
	if writeErr == nil {
		writeErr = tw.Close()
	}
	if writeErr == nil {
		writeErr = gz.Close()
	}
	return errors.Join(writeErr, out.Close())
}

func addFile(tw *tar.Writer, src, rel string) error {
	file, err := os.Open(filepath.Join(src, filepath.FromSlash(rel)))
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return errors.Join(err, file.Close())
	}
	hdr := &tar.Header{
		Name:     e2eConfigDir + "/" + rel,
		Mode:     0o644,
		Size:     info.Size(),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return errors.Join(err, file.Close())
	}
	_, err = io.Copy(tw, file)
	return errors.Join(err, file.Close())
}
