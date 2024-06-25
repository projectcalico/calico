package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
)

const (
	makefileConfigFile = "metadata.mk"
)

func MustReadGitRepoPath() string {
	repoRootDir, err := ReadGitRepoPath()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to get repo root")
	}
	return repoRootDir
}

func ReadGitRepoPath() (string, error) {
	repoRootCmd := exec.Command("git", "rev-parse", "--show-toplevel")
	var out bytes.Buffer
	repoRootCmd.Stdout = &out
	err := repoRootCmd.Run()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func MustReadMakefileValue(path string, key string) string {
	value, err := ReadMakefileValue(path, key)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"Makefile config file": path,
			"key":                  key,
		}).Fatal("Failed to read Makefile value")
	}
	return value
}

func ReadMakefileValue(path string, key string) (string, error) {
	logrus.WithFields(logrus.Fields{
		"Makefile config file": path,
		"key":                  key,
	}).Debug("Reading Makefile value")
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(fmt.Sprintf(`^%s\s*=\s*\S+$`, regexp.QuoteMeta(key)))
	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			return strings.TrimSpace(match[0][len(key)+1:]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("key %s not found in %s", key, path)
}
