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

package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

const (
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

// LinkOrCopyFiles keeps each file's path relative to srcDir under dstDir.
func LinkOrCopyFiles(srcDir, dstDir string, files []string) error {
	for _, src := range files {
		relPath, err := filepath.Rel(srcDir, src)
		if err != nil {
			return fmt.Errorf("relative path of %s: %w", src, err)
		}
		dst := filepath.Join(dstDir, relPath)
		if err := os.MkdirAll(filepath.Dir(dst), DirPerms); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", dst, err)
		}
		if err := LinkOrCopyFile(src, dst); err != nil {
			return fmt.Errorf("failed to copy %s to %s: %w", src, dst, err)
		}
	}
	return nil
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
