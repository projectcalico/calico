package operator

import (
	"fmt"
)

type Config struct {
	// GitRemote is the remote for the git repository
	GitRemote string `envconfig:"OPERATOR_GIT_REMOTE" default:"origin"`

	// GitOrganization is the organization for the operator
	GitOrganization string `envconfig:"OPERATOR_GIT_ORGANIZATION" default:"tigera"`

	// GitRepository is the repository for the operator
	GitRepository string `envconfig:"OPERATOR_GIT_REPOSITORY" default:"operator"`

	// Branch is the repository for the operator
	Branch string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// RepoReleaseBranchPrefix is the prefix for the release branch
	RepoReleaseBranchPrefix string `envconfig:"OPERATOR_RELEASE_BRANCH_PREFIX" default:"release"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"OPERATOR_DEV_TAG_SUFFIX" default:"0.dev"`

	// Dir is the directory to clone the operator repository
	Dir string `envconfig:"OPERATOR_DIR"`

	// Image is the image for Tigera operator
	Image string `envconfig:"OPERATOR_IMAGE" default:"tigera/operator"`

	// Registry is the registry for Tigera operator
	Registry string `envconfig:"OPERATOR_REGISTRY" default:"quay.io"`
}

func (c Config) Repo() string {
	return fmt.Sprintf("git@github.com:%s/%s.git", c.GitOrganization, c.GitRepository)
}

func (c Config) String() string {
	return fmt.Sprintf("Repo: %s, Branch: %s, Image: %s, Registry: %s", c.Repo(), c.Branch, c.Image, c.Registry)
}
