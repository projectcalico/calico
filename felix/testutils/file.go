package testutils

import (
	"os"
	"path"
)

func TestDataFile(name string) string {
	dir, _ := os.Getwd()

	return path.Join(dir, "testdata", name)
}
