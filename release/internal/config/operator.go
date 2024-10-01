package config

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/version"
)

type OperatorConfig struct {
	// GitRemote is the remote for the git repository
	GitRemote string `envconfig:"OPERATOR_GIT_REMOTE" default:"origin"`

	// Organization is the GitHub organization for the operator
	Organization string `envconfig:"OPERATOR_GIT_ORGANIZATION" default:"tigera"`

	// GitRepository is the repository for the operator
	GitRepository string `envconfig:"OPERATOR_GIT_REPOSITORY" default:"operator"`

	// Branch is the repository for the operator
	Branch string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// RepoReleaseBranchPrefix is the prefix for the release branch
	RepoReleaseBranchPrefix string `envconfig:"OPERATOR_RELEASE_BRANCH_PREFIX" default:"release"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"OPERATOR_DEV_TAG_SUFFIX" default:"0.dev"`

	// Dir is the directory to clone the operator repository.
	Dir string

	// Image is the image for Tigera operator
	Image string `envconfig:"OPERATOR_IMAGE" default:"tigera/operator"`

	// Registry is the registry for Tigera operator
	Registry string `envconfig:"OPERATOR_REGISTRY" default:"quay.io"`
}

func (c OperatorConfig) Repo() string {
	return fmt.Sprintf("git@github.com:%s/%s.git", c.Organization, c.GitRepository)
}

func (c OperatorConfig) GitVersion() version.Version {
	previousTag, err := command.GitVersion(c.Dir, true)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to determine latest git version")
	}
	logrus.WithField("out", previousTag).Info("Current git describe")
	return version.New(previousTag)
}

func (c OperatorConfig) GitBranch() (string, error) {
	return command.GitInDir(c.Dir, "rev-parse", "--abbrev-ref", "HEAD")
}

func (c OperatorConfig) String() string {
	return fmt.Sprintf("Repo: %s, Branch: %s, Image: %s, Registry: %s", c.Repo(), c.Branch, c.Image, c.Registry)
}
