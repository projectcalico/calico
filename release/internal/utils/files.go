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
	"fmt"
	"os"
	"path/filepath"
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
