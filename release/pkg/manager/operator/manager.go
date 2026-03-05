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

package operator

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	DefaultImage               = registry.TigeraOperatorImage
	DefaultOrg                 = utils.TigeraOrg
	DefaultRepoName            = "operator"
	DefaultRemote              = utils.DefaultRemote
	DefaultBranchName          = utils.DefaultBranch
	DefaultReleaseBranchPrefix = "release"
	DefaultDevTagSuffix        = "0.dev"
	DefaultRegistry            = "quay.io"
)

type OperatorManager struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner command.CommandRunner

	// version is the operator version
	version string

	// dir is the absolute path to the root directory of the operator repository
	dir string

	// calicoDir is the absolute path to the root directory of the calico repository
	calicoDir string

	calicoVersion string

	// tmpDir is the absolute path to the temporary directory
	tmpDir string

	// outputDir is the absolute path to the output directory
	outputDir string

	// image is the name of the operator image (e.g. tigera/operator)
	image string

	// registry is the registry to use for operator (e.g. quay.io)
	registry string

	// productRegistry is the registry to use for product images (e.g. quay.io/calico)
	productRegistry string

	// origin remote repository
	remote string

	// githubOrg is the organization of the repository
	githubOrg string

	// repoName is the name of the repository
	repoName string

	// branch is the branch to use
	branch string

	// devTag is the development tag identifier
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch
	releaseBranchPrefix string

	// isHashRelease indicates if we are doing a hashrelease
	isHashRelease bool

	// validate indicates if we should run validation
	validate bool

	// validateBranch indicates if we should run branch validation
	validateBranch bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool

	// architectures is the list of architectures for which we should build images.
	// If empty, we build for all.
	architectures []string
}

func NewManager(opts ...Option) *OperatorManager {
	o := &OperatorManager{
		runner:          &command.RealCommandRunner{},
		registry:        DefaultRegistry,
		image:           DefaultImage,
		productRegistry: registry.DefaultCalicoRegistries[0],
		validate:        true,
		publish:         true,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	return o
}

func (o *OperatorManager) Build() error {
	if o.validate {
		if err := o.PreBuildValidation(); err != nil {
			return err
		}
	}
	env, logFields, err := o.buildEnv()
	if err != nil {
		return fmt.Errorf("env vars for building operator: %s", err)
	}
	logrus.WithFields(logFields).Info("Building operator")
	out, err := o.make("release", env)
	if err != nil {
		return fmt.Errorf("failed to build operator: %s: %s", err, out)
	}
	logrus.WithFields(logFields).Infof("Built operator: %s", out)
	return nil
}

func (o *OperatorManager) buildEnv() ([]string, logrus.Fields, error) {
	logFields := logrus.Fields{
		"registry": o.registry,
		"image":    o.image,
		"version":  o.version,
	}
	env := append(os.Environ(),
		fmt.Sprintf("REGISTRY=%s", o.registry),
		fmt.Sprintf("IMAGE=%s", o.image),
		fmt.Sprintf("VERSION=%s", o.version),
	)
	if o.isHashRelease {
		env = append(env,
			fmt.Sprintf("HASHRELEASE=true"),
			fmt.Sprintf("CALICO_VERSION=%s", o.calicoVersion),
			fmt.Sprintf("CALICO_DIR=%s", o.calicoDir),
		)
		logFields["hashrelease"] = "true"
		logFields["calico_version"] = o.calicoVersion
		logFields["calico_dir"] = o.calicoDir
	}
	if len(o.architectures) > 0 {
		archs := strings.Join(o.architectures, ",")
		env = append(env, fmt.Sprintf("ARCHS=%s", archs))
		logFields["arch"] = archs
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		env = append(env, "DEBUG=true")
	}
	return env, logFields, nil
}

func (o *OperatorManager) PreBuildValidation() error {
	var errStack error
	if o.dir == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no repository root specified"))
	}
	if !o.validateBranch {
		return nil
	}
	branch, err := utils.GitBranch(o.dir)
	if err != nil {
		return fmt.Errorf("failed to determine branch: %s", err)
	}
	match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, o.releaseBranchPrefix)
	re := regexp.MustCompile(match)
	if !re.MatchString(branch) {
		errStack = errors.Join(errStack, fmt.Errorf("not on a release branch"))
	}
	dirty, err := utils.GitIsDirty(o.dir)
	if err != nil {
		return fmt.Errorf("failed to check if git is dirty: %s", err)
	}
	if dirty {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before building the hashrelease"))
	}
	return errStack
}

func (o *OperatorManager) Publish() error {
	if !o.publish {
		logrus.Warn("Skipping publishing operator")
		return nil
	}

	env, logFields, err := o.buildEnv()
	if err != nil {
		return fmt.Errorf("env vars for publishing operator: %s", err)
	}
	logrus.WithFields(logFields).Info("Publishing operator")
	out, err := o.make("release-publish", env)
	if err != nil {
		return fmt.Errorf("failed to publish operator: %s: %s", err, out)
	}
	logrus.WithFields(logFields).Infof("Published operator: %s", out)
	return nil
}

// ReleasePublic publishes the current draft release of the operator to make it publicly available.
// It determines the latest release version, compares it with the current version, and marks the release as the latest if applicable.
func (o *OperatorManager) ReleasePublic() error {
	env := append(os.Environ(), fmt.Sprintf("VERSION=%s", o.version))
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		env = append(env, "DEBUG=true")
	}
	out, err := o.make("release-public", env)
	if err != nil {
		return fmt.Errorf("failed to release operator: %s: %s", err, out)
	}
	return nil
}

func (o *OperatorManager) make(target string, env []string) (string, error) {
	return o.runner.Run("make", []string{"-C", o.dir, target}, env)
}

func Clone(org, repo, branch, dir string) error {
	return utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", org, repo), branch, dir)
}
