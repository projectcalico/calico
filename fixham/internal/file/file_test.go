package file

import (
	"os"
	"testing"
)

func setup() {
	_ = os.RemoveAll("file_test_dir")
}

func TestCreateDirIfNotExist(t *testing.T) {
	setup()
	t.Cleanup(setup)
	// Test case: directory does not exist
	dirPath := "file_test_dir"
	err := CreateDirIfNotExist(dirPath)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify that the directory was created
	_, err = os.Stat(dirPath)
	if os.IsNotExist(err) {
		t.Errorf("Expected directory to be created, but it does not exist")
	}

	// Test case: directory already exists
	existingDirPath := "file_test_dir"
	err = os.MkdirAll(existingDirPath, os.ModePerm)
	if err != nil {
		t.Fatalf("Failed to create existing directory: %v", err)
	}
	err = CreateDirIfNotExist(existingDirPath)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Verify that the existing directory was not modified
	_, err = os.Stat(existingDirPath)
	if err != nil {
		t.Errorf("Expected existing directory to still exist, but got error: %v", err)
	}
}
