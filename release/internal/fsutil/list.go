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

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// FileFilter narrows the files listed so far. ListFiles runs a series of them,
// starting from no files.
type FileFilter func(dir string, files ...string) ([]string, error)

func ListFiles(dir string, filters ...FileFilter) ([]string, error) {
	var files []string
	for _, filter := range filters {
		var err error
		if files, err = filter(dir, files...); err != nil {
			return nil, fmt.Errorf("list files: %w", err)
		}
	}
	return files, nil
}

// DirFiles lists the regular files directly in dir, replacing the files so far.
func DirFiles(dir string, _ ...string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []string
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	return out, nil
}

// Recursive lists regular files at any depth under dir, replacing the files so far.
func Recursive(dir string, _ ...string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", path, err)
		}
		if entry.Type().IsRegular() {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("recursive: %w", err)
	}
	return out, nil
}

// Match keeps the files keep accepts, given each file's path relative to dir.
func Match(keep func(relPath string) bool) FileFilter {
	return func(dir string, files ...string) ([]string, error) {
		var out []string
		for _, file := range files {
			relPath, err := filepath.Rel(dir, file)
			if err != nil {
				return nil, fmt.Errorf("match: relative path of %s: %w", file, err)
			}
			if keep(relPath) {
				out = append(out, file)
			}
		}
		return out, nil
	}
}

// Exclude leaves out files whose base name matches any of the globs.
func Exclude(globs ...string) FileFilter {
	return func(_ string, files ...string) ([]string, error) {
		var out []string
		for _, file := range files {
			excluded := false
			for _, glob := range globs {
				matched, err := filepath.Match(glob, filepath.Base(file))
				if err != nil {
					return nil, fmt.Errorf("exclude: glob %q: %w", glob, err)
				}
				if matched {
					excluded = true
					break
				}
			}
			if !excluded {
				out = append(out, file)
			}
		}
		return out, nil
	}
}

// Include takes names relative to dir. It fails when a name is not among the
// files, so a lost file is not silently skipped.
func Include(names ...string) FileFilter {
	return func(dir string, files ...string) ([]string, error) {
		var out []string
		var errs []error
		for _, name := range names {
			idx := slices.IndexFunc(files, func(file string) bool {
				relPath, err := filepath.Rel(dir, file)
				return err == nil && relPath == name
			})
			if idx < 0 {
				errs = append(errs, fmt.Errorf("include: %s not found in %s", name, dir))
				continue
			}
			out = append(out, files[idx])
		}
		if err := errors.Join(errs...); err != nil {
			return nil, fmt.Errorf("include: %w", err)
		}
		return out, nil
	}
}

// IsRegular drops directories and symlinks, and fails on a file it cannot lstat.
func IsRegular(files ...string) ([]string, error) {
	var out []string
	var errs []error
	for _, file := range files {
		info, err := os.Lstat(file)
		if err != nil {
			errs = append(errs, fmt.Errorf("is regular: lstat %s: %w", file, err))
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		out = append(out, file)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("is regular: %w", err)
	}
	return out, nil
}
