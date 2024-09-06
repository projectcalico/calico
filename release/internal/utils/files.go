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
