package main

import (
	"flag"
	"os"

	"github.com/projectcalico/calico/hack/release/pkg/builder"
	"github.com/sirupsen/logrus"
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
		err := r.BuildRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to create Calico release")
			os.Exit(1)
		}
		return
	}

	if publish {
		err := r.PublishRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to publish Calico release")
			os.Exit(1)
		}
		return
	}

	if newBranch {
		err := r.NewBranch()
		if err != nil {
			logrus.WithError(err).Error("Failed to create new release branch")
			os.Exit(1)
		}
		return
	}

	logrus.Fatalf("No command specified")
}
