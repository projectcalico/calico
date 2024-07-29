package tasks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
)

func removePath(path string) {
	err := os.RemoveAll(path)
	if err != nil {
		logrus.WithField("path", path).WithError(err).Warn("removing file failed")
	}

}

func CleanFiles(paths ...string) {
	for _, p := range paths {
		if strings.Contains(p, "*?[") {
			matches, err := filepath.Glob(p)
			if err != nil {
				logrus.WithField("path", p).WithError(err).Warn("expanding wildcard failed")
			}
			for _, m := range matches {
				removePath(m)
			}
		} else {
			removePath(p)
		}
	}
}

func CleanImages(images ...string) {
	for _, image := range images {
		runner := registry.MustDockerRunner()
		err := runner.RemoveImage(image)
		if err != nil {
			logrus.WithField("image", image).WithError(err).Fatal("removing image failed")
		}
	}
}

func Clean(paths []string, images []string) {
	CleanFiles(paths...)
	CleanImages(images...)
}

func ResetRepo(dir string) {
	_, err := command.GitInDir(dir, "checkout", "HEAD")
	if err != nil {
		logrus.WithError(err).Fatal("failed to reset repo")
	}
}
