package main

import (
	"flag"
	"io"
	"os"

	"github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/projectcalico/calico/hack/release/pkg/builder"
)

var create, publish, newBranch bool

func init() {
	flag.BoolVar(&create, "create", false, "Create a release from the current commit")
	flag.BoolVar(&publish, "publish", false, "Publish the release built from the current tag")
	flag.BoolVar(&newBranch, "new-branch", false, "Create a new release branch from master")

	flag.Parse()
}

func main() {
	// Create a releaseBuilder to use.
	r := builder.NewReleaseBuilder(&builder.RealCommandRunner{})

	// Uncomment this to echo out commands that would be run, rather than running them!
	//
	// echoRunner := &echoRunner{
	// 	responses: map[string]string{
	// 		"git rev-parse --abbrev-ref HEAD":                  "release-v4.15",
	// 		"git describe --tags --dirty --always --abbrev=12": "v4.16.0-0.dev-24850-ga7254d42ad39",
	// 	},
	// 	errors: map[string]error{
	// 		"git describe --exact-match --tags HEAD": fmt.Errorf("Not on a tag"),
	// 	},
	// }
	// r = builder.NewReleaseBuilder(&echoRunner)

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
