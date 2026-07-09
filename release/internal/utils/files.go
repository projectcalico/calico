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

package utils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	// ReleaseFolderName is the name of the release tool in this repository.
	ReleaseFolderName = "release"

	// DirPerms is the permissions for directories.
	DirPerms os.FileMode = 0o755
)

// MoveFile moves a file from srcPattern to dstFile.
// srcPattern should match exactly one file.
func MoveFile(srcPattern, dstFile string) error {
	files, err := filepath.Glob(srcPattern)
	if err != nil {
		return fmt.Errorf("failed to find files matching pattern %s: %s", srcPattern, err)
	}
	if len(files) != 1 {
		return fmt.Errorf("expected to find exactly one file matching pattern %s, but found %d", srcPattern, len(files))
	}
	srcFile := files[0]
	if err := os.Rename(srcFile, dstFile); err != nil {
		return fmt.Errorf("failed to move file %s to %s: %v", srcFile, dstFile, err)
	}
	return nil
}

func CopyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, 0o644)
	if err != nil {
		fmt.Println("Error creating", dst)
		return err
	}
	return nil
}

// IncludeFunc decides whether LinkOrCopyDir should copy a particular file.
// It is given srcDir and dstDir (the roots passed to LinkOrCopyDir) and
// relPath, the file's path relative to srcDir. srcDir and dstDir are passed
// so implementations can filter on more than the file name — for example by
// os.Stat-ing the source file or inspecting an existing destination.
type IncludeFunc func(srcDir, dstDir, relPath string) bool

// LinkOrCopyDir recursively scans srcDir for files and copies them into dstDir,
// preserving the relative directory structure. The include function is called
// for each regular file; the file is copied only when include returns true.
// Intermediate directories are created as needed.
func LinkOrCopyDir(srcDir, dstDir string, include IncludeFunc) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to determine relative path for %s: %w", path, err)
		}
		if !include(srcDir, dstDir, relPath) {
			return nil
		}
		dst := filepath.Join(dstDir, relPath)
		if err := os.MkdirAll(filepath.Dir(dst), DirPerms); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", dst, err)
		}
		if err := LinkOrCopyFile(path, dst); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", path, dst, err)
		}
		return nil
	})
}

// FindRecursiveFiles recursively scans srcDir for files and returns the paths
// of those for which include returns true. Like LinkOrCopyDir, the include
// function is called for each regular file with srcDir, relPath (the file's
// path relative to srcDir), and an empty dstDir — there is no destination when
// merely finding files — so the same IncludeFunc can be shared between the two.
// Returned paths are joined with srcDir (i.e. filepath.Join(srcDir, relPath)).
func FindRecursiveFiles(srcDir string, include IncludeFunc) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("failed to determine relative path for %s: %w", path, err)
		}
		if !include(srcDir, "", relPath) {
			return nil
		}
		matches = append(matches, filepath.Join(srcDir, relPath))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// MatchRegexp returns an IncludeFunc that matches a file's base name against
// the given regular expression.
func MatchRegexp(pattern string) (IncludeFunc, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp %q: %w", pattern, err)
	}
	return func(_, _, relPath string) bool {
		return re.MatchString(filepath.Base(relPath))
	}, nil
}

// MatchGlobs returns an IncludeFunc that matches a file's base name against
// any of the given shell globs (see filepath.Match). The globs are validated
// up front so callers learn about malformed patterns before the returned
// function is used.
func MatchGlobs(globs ...string) (IncludeFunc, error) {
	for _, glob := range globs {
		if _, err := filepath.Match(glob, ""); err != nil {
			return nil, fmt.Errorf("invalid glob %q: %w", glob, err)
		}
	}
	return func(_, _, relPath string) bool {
		base := filepath.Base(relPath)
		for _, glob := range globs {
			// Errors are impossible here: every glob was validated above.
			if ok, _ := filepath.Match(glob, base); ok {
				return true
			}
		}
		return false
	}, nil
}

// MatchExtensions returns an IncludeFunc that matches a file whose extension
// is any of the given ones. Extensions may be supplied with or without a
// leading dot (e.g. "txt" or ".txt") and are matched case-insensitively.
func MatchExtensions(exts ...string) IncludeFunc {
	want := make(map[string]struct{}, len(exts))
	for _, ext := range exts {
		want[strings.ToLower("."+strings.TrimPrefix(ext, "."))] = struct{}{}
	}
	return func(_, _, relPath string) bool {
		_, ok := want[strings.ToLower(filepath.Ext(relPath))]
		return ok
	}
}

// LinkOrCopyFile creates a hard link at dst pointing to src, falling back to
// copying the file contents if the link cannot be created (e.g. src and dst
// are on different filesystems, or the filesystem does not support hard
// links). Any pre-existing file at dst is removed first so os.Link does not
// fail with an "already exists" error. Once the file is copied, we also
// copy the file mode (e.g. executable bits, read/write perms) from the
// original file.
func LinkOrCopyFile(src, dst string) error {
	logrus.WithFields(logrus.Fields{
		"src": src,
		"dst": dst,
	}).Debug("copying file")
	if err := os.Remove(dst); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := CopyFile(src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, info.Mode())
}

func pathInfo(path string) (os.FileInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for %s: %w", path, err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get info for path %s: %w", absPath, err)
	}
	return info, nil
}

// DirExists validates if a given (relative or absolute) path exists and
// is a directory (or as symlink to one)
func DirExists(path string) (bool, error) {
	info, err := pathInfo(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

// FileExists validates if a given (relative or absolute) path exists
// and is a regular file
func FileExists(path string) (bool, error) {
	info, err := pathInfo(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

// PathExists reports whether path exists. It returns (false, nil) only when
// the path is genuinely absent; any other Stat failure (permission denied,
// malformed path, etc.) is surfaced so callers do not silently skip work.
func PathExists(path string) (bool, error) {
	_, err := pathInfo(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CheckBinary searches the current PATH for a binary and returns an error if it's not found
func CheckBinary(binaryName, neededFor string) error {
	if path, err := exec.LookPath(binaryName); err != nil {
		logrus.WithError(err).Errorf("Error trying to find %s in PATH (needed for %s)", binaryName, neededFor)
		return fmt.Errorf("unable to find %s in PATH (needed for %s)", binaryName, neededFor)
	} else if path == "" {
		logrus.Errorf("%s not found in PATH (needed for %s)", binaryName, neededFor)
		return fmt.Errorf("%s not found in PATH (needed for %s)", binaryName, neededFor)
	}
	return nil
}

// FilterRegularFiles accepts a list of file paths and returns a list
// of regular files (i.e. not dirs or symlinks) which existed and were
// accessible (i.e. the lstat() call succeeded).
func FilterRegularFiles(filePathList []string) ([]string, error) {
	var filteredFilesList []string
	for _, filePath := range filePathList {
		fileStat, err := os.Lstat(filePath)
		if err != nil {
			logrus.WithError(err).Warn("failed to lstat file")
			return []string{}, fmt.Errorf("unable to lstat %s: %w", filePath, err)
		}

		if fileStat.Mode().Type().IsRegular() {
			filteredFilesList = append(filteredFilesList, filePath)
			continue
		}
		logrus.Debugf("removing file path %s as it is not a regular file", filePath)
	}
	return filteredFilesList, nil
}
