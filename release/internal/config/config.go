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
	"path/filepath"

	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/imagescanner"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/slack"
	"github.com/projectcalico/calico/release/internal/utils"
)

type Config struct {
	// Organization is the name of the organization
	Organization string `envconfig:"ORGANIZATION" default:"projectcalico"`

	// RepoRootDir is the root directory for this repository
	RepoRootDir string `envconfig:"REPO_ROOT"`

	// DevTagSuffix is the suffix for the development tag
	DevTagSuffix string `envconfig:"DEV_TAG_SUFFIX" default:"0.dev"`

	// RepoReleaseBranchPrefix is the suffix for the release tag
	RepoReleaseBranchPrefix string `envconfig:"RELEASE_BRANCH_PREFIX" default:"release"`

	// GitRemote is the remote for the git repository
	GitRemote string `envconfig:"GIT_REMOTE" default:"origin"`

	// Operator is the configuration for Tigera operator
	Operator OperatorConfig

	// Arches are the OS architectures supported for multi-arch build
	Arches []string `envconfig:"ARCHES" default:"amd64,arm64,ppc64le,s390x"`

	// DocsHost is the host for the hashrelease docs
	DocsHost string `envconfig:"DOCS_HOST"`

	// DocsPort is the port for the hashrelease docs
	DocsPort string `envconfig:"DOCS_PORT"`

	// DocsPath is the path for the hashrelease docs
	DocsUser string `envconfig:"DOCS_USER"`

	// DocsPath is the path for the hashrelease docs
	DocsKey string `envconfig:"DOCS_KEY"`

	// GithubToken is the token for the GitHub API
	GithubToken string `envconfig:"GITHUB_TOKEN"`

	// OutputDir is the directory for the output
	OutputDir string `envconfig:"OUTPUT_DIR"`

	// SlackConfig is the configuration for Slack integration
	SlackConfig slack.Config

	// ImageScannerConfig is the configuration for Image Scanning Service integration
	ImageScannerConfig imagescanner.Config

	CI CIConfig
}

// TmpFolderPath returns the temporary folder path.
// This is used for temporary files during the release process
func (c *Config) TmpFolderPath() string {
	return filepath.Join(c.RepoRootDir, utils.ReleaseFolderName, "tmp")
}

// repoRootDir returns the root directory of this repository
func repoRootDir() string {
	dir, err := command.GitDir("")
	if err != nil {
		logrus.WithError(err).Fatal("failed to get repo root dir")
	}
	return dir
}

// LoadConfig loads the configuration from the environment
func LoadConfig() *Config {
	config := &Config{}
	envconfig.MustProcess("", config)
	if config.RepoRootDir == "" {
		config.RepoRootDir = repoRootDir()
	}
	if config.OutputDir == "" {
		config.OutputDir = filepath.Join(config.RepoRootDir, utils.ReleaseFolderName, "_output")
	}
	if config.Operator.Dir == "" {
		config.Operator.Dir = filepath.Join(config.TmpFolderPath(), config.Operator.GitRepository)
	}
	config.Operator.Registry = registry.QuayRegistry
	config.Operator.Image = OperatorDefaultImage
	return config
}
