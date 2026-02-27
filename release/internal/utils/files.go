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

// PathExists validates if a given (relative or absolute) path exists
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// DirExists validates if a given (relative or absolute) path exists and
// is a directory (or as symlink to one)
func DirExists(path string) (bool, error) {
	stat, err := os.Stat(path)
	if err == nil {
		return stat.IsDir(), nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
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
