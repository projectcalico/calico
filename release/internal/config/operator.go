// Copyright (c) 2024 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/version"
)

const (
	OperatorDefaultImage = "tigera/operator"
	OperatorDefaultOrg   = "tigera"
	OperatorDefaultRepo  = "operator"
)

type OperatorConfig struct {
	// GitRemote is the remote for the git repository
	GitRemote string `envconfig:"OPERATOR_GIT_REMOTE" default:"origin"`

	// Branch is the repository for the operator
	Branch string `envconfig:"OPERATOR_BRANCH" default:"master"`

	// RepoReleaseBranchPrefix is the prefix for the release branch
	RepoReleaseBranchPrefix string `envconfig:"OPERATOR_RELEASE_BRANCH_PREFIX" default:"release"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"OPERATOR_DEV_TAG_SUFFIX" default:"0.dev"`

	// Dir is the directory to clone the operator repository.
	Dir string

	// Image is the image for Tigera operator
	Image string

	// Registry is the registry for Tigera operator
	Registry string
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
