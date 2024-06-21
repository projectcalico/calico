package bootstrap

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/goyek/goyek/v2"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/ctl/pkg/ctl"
)

var Clean *goyek.DefinedTask

func removeFile(path string) {
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
				removeFile(m)
			}
		} else {
			removeFile(p)
		}
	}
}

func cleanImages(images ...string) {
	for _, image := range images {
		runner := ctl.NewDockerRunner(image)
		runner.RemoveImage()
	}
}

func DefineCleanTask(paths []string, images []string, deps goyek.Deps) *goyek.DefinedTask {
	Clean = goyek.Define(goyek.Task{
		Name:  "clean",
		Usage: "Clean the project",
		Action: func(a *goyek.A) {
			a.Log("Cleaning project")
			cleanFiles(paths...)
			cleanImages(images...)
		},
		Deps:     deps,
		Parallel: false,
	})
	return Clean
}
