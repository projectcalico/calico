package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

func getSemaphoreDirs(dir string) ([]string, error) {
	var dirs []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && filepath.Base(path) == ".semaphore" {
			dirs = append(dirs, path)
		}
		return nil
	})
	return dirs, err
}

func getYAMLFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip the YAML .semaphore/semaphore.yml.d directory
		if info.IsDir() && strings.HasSuffix(path, "semaphore.yml.d") {
			return filepath.SkipDir
		}
		if !info.IsDir() && (filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func validateYAML(file string) error {
	logrus.WithField("file", file).Info("validating YAML")
	content, err := os.ReadFile(file)
	if err != nil {
		logrus.WithError(err).Error("failed to read file")
		return err
	}
	payload := map[string]string{
		"yaml_definition": fmt.Sprintf("%v", string(content)),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal payload for yaml validation")
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://tigera.semaphoreci.com/api/v1alpha/yaml", bytes.NewBuffer(data))
	if err != nil {
		logrus.WithError(err).Error("failed to create request for yaml validation")
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", os.Getenv("SEMAPHORE_API_TOKEN")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithError(err).Error("failed to make request for yaml validation")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to validate YAML: %s", resp.Status)
	}
	result := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logrus.WithError(err).Error("failed to decode response for yaml validation")
		return err
	}
	logrus.Info(result["message"].(string))
	return nil
}

func main() {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		logrus.WithError(err).Fatal("failed to get repo root dir")
	}
	dir := strings.TrimSpace(string(out))
	semaphoreDirs, err := getSemaphoreDirs(dir)
	logrus.WithField("semaphoreDirs", semaphoreDirs).Debug("found semaphore directories")
	if err != nil {
		logrus.WithError(err).Fatal("failed to get semaphore directories")
	}
	var yamlFiles []string
	for _, semaphoreDir := range semaphoreDirs {
		files, err := getYAMLFiles(semaphoreDir)
		if err != nil {
			logrus.WithError(err).Errorf("failed to get YAML files in %s", semaphoreDir)
			continue
		}
		yamlFiles = append(yamlFiles, files...)
	}
	if len(yamlFiles) == 0 {
		logrus.Info("no YAML files found")
		return
	}
	logrus.WithField("yamlFiles", yamlFiles).Debug("found YAML files")
	var failedFiles []string
	for _, file := range yamlFiles {
		err = validateYAML(file)
		if err != nil {
			logrus.WithError(err).Error("invalid YAML definition")
			failedFiles = append(failedFiles, file)
		}
	}
	if len(failedFiles) > 0 {
		logrus.Fatalf("failed to validate %d files", len(failedFiles))
	}
}
