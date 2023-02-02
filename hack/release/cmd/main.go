package main

import (
	"flag"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/hack/release/pkg/builder"
)

var create, publish, newBranch, meta bool
var dir string

func init() {
	flag.BoolVar(&create, "create", false, "Create a release from the current commit")
	flag.BoolVar(&publish, "publish", false, "Publish the release built from the current tag")
	flag.BoolVar(&newBranch, "new-branch", false, "Create a new release branch from master")
	flag.BoolVar(&meta, "metadata", false, "Product release metadata")

	flag.StringVar(&dir, "dir", "./", "Directory to place build metadata in")

	flag.Parse()
}

func main() {
	// Create a releaseBuilder to use.
	r := builder.NewReleaseBuilder(&builder.RealCommandRunner{})

	if meta {
		configureLogging("metadata.log")
		err := r.BuildMetadata(dir)
		if err != nil {
			logrus.WithError(err).Error("Failed to produce release metadata")
			os.Exit(1)
		}
		return
	}

	if create {
		configureLogging("release-build.log")
		err := r.BuildRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to create Calico release")
			os.Exit(1)
		}
		return
	}

	if publish {
		configureLogging("release-publish.log")
		err := r.PublishRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to publish Calico release")
			os.Exit(1)
		}
		return
	}

	if newBranch {
		configureLogging("cut-release-branch.log")
		err := r.NewBranch()
		if err != nil {
			logrus.WithError(err).Error("Failed to create new release branch")
			os.Exit(1)
		}
		return
	}

	logrus.Fatalf("No command specified")
}

func configureLogging(filename string) {
	// Set up logging to both stdout as well as a file.
	writers := []io.Writer{os.Stdout, &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    100,
		MaxAge:     30,
		MaxBackups: 10,
	}}
	logrus.SetOutput(io.MultiWriter(writers...))
}
