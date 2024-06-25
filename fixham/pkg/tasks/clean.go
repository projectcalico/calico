package tasks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/fixham/internal/docker"
)

func removePath(path string) {
	err := os.RemoveAll(path)
	if err != nil {
		logrus.WithField("path", path).WithError(err).Warn("removing file failed")
	}

}

func cleanFiles(paths ...string) {
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

func cleanImages(images ...string) {
	for _, image := range images {
		runner := docker.MustDockerRunner()
		err := runner.RemoveImage(image)
		if err != nil {
			logrus.WithField("image", image).WithError(err).Fatal("removing image failed")
		}
	}
}

func DefineCleanTask(paths []string, images []string, deps goyek.Deps) *goyek.DefinedTask {
	return RegisterTask(goyek.Task{
		Name:  "clean",
		Usage: "Clean the project",
		Action: func(a *goyek.A) {
			logrus.Debug("Cleaning project")
			cleanFiles(paths...)
			cleanImages(images...)
		},
		Deps:     deps,
		Parallel: false,
	})
}
