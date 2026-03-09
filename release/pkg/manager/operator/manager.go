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
	DefaultBranchName          = utils.DefaultBranch
	DefaultReleaseBranchPrefix = "release"
	DefaultRegistry            = "quay.io"
)

var (
	defaultProductEnvPrefix = "CALICO"
	defaultProductRegistry  = registry.DefaultCalicoRegistries[0]
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

	// image is the name of the operator image (e.g. tigera/operator)
	image string

	// registry is the registry to use for operator (e.g. quay.io)
	registry string

	// productRegistry is the registry to use for product images (e.g. quay.io/calico)
	productRegistry string

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
		runner:   &command.RealCommandRunner{},
		registry: DefaultRegistry,
		image:    DefaultImage,
		validate: true,
		publish:  true,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}
	if o.productRegistry == "" {
		o.productRegistry = defaultProductRegistry
	}
	return o
}

func (o *OperatorManager) Build() error {
	if err := o.PreBuildValidation(); err != nil {
		return err
	}
	env, logFields := o.env()
	logFields["calico_registry"] = o.productRegistry
	r, i, err := o.productRegistryParts()
	if err != nil {
		return err
	}
	env = append(env, fmt.Sprintf("%s_REGISTRY=%s", defaultProductEnvPrefix, r))
	env = append(env, fmt.Sprintf("%s_IMAGE_PATH=%s", defaultProductEnvPrefix, i))
	if o.isHashRelease {
		if o.calicoVersion != "" {
			env = append(env, fmt.Sprintf("%s_VERSION=%s", defaultProductEnvPrefix, o.calicoVersion))
			logFields["calico_version"] = o.calicoVersion
		}
		if o.calicoDir != "" {
			env = append(env, fmt.Sprintf("%s_DIR=%s", defaultProductEnvPrefix, o.calicoDir))
			logFields["calico_dir"] = o.calicoDir
		}
	}
	logrus.WithFields(logFields).Info("Building operator")
	out, err := o.make("release", env)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to build operator: %w", err)
	}
	logrus.WithFields(logFields).Infof("Built operator: %s", out)
	return nil
}

func (o *OperatorManager) env() ([]string, logrus.Fields) {
	logFields := logrus.Fields{
		"registry": o.registry,
		"image":    o.image,
		"version":  o.version,
	}
	env := append(os.Environ(),
		fmt.Sprintf("REGISTRY=%s", o.registry),
		fmt.Sprintf("IMAGE_NAME=%s", o.image),
		fmt.Sprintf("VERSION=%s", o.version),
	)
	if o.isHashRelease {
		logFields["hashrelease"] = "true"
		env = append(env, "HASHRELEASE=true")
	}
	if len(o.architectures) > 0 {
		archs := strings.Join(o.architectures, ",")
		env = append(env, fmt.Sprintf("ARCHS=%s", archs))
		logFields["arch"] = archs
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		env = append(env, "DEBUG=true")
	}
	return env, logFields
}

// productRegistryParts splits the product registry into registry and image path.
// Typically the product registry is something like "docker.io/calico" or "quay.io/calico".
// This function splits it into "docker.io" and "calico" or "quay.io" and "calico".
func (o *OperatorManager) productRegistryParts() (registry string, imagePath string, err error) {
	parts := strings.Split(o.productRegistry, "/")
	if len(parts) < 2 {
		err = fmt.Errorf("failed to parse product registry: %s", o.productRegistry)
		return
	}
	registry = strings.Join(parts[:len(parts)-1], "/")
	imagePath = parts[len(parts)-1]
	return
}

func (o *OperatorManager) PreBuildValidation() error {
	if !o.validate {
		return nil
	}
	if o.dir == "" {
		return fmt.Errorf("no repository root specified")
	}
	var errStack error
	dirty, err := utils.GitIsDirty(o.dir)
	if err != nil {
		return fmt.Errorf("failed to check if git is dirty: %w", err)
	}
	if dirty {
		errStack = errors.Join(errStack, fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them"))
	}
	if o.isHashRelease && (o.calicoVersion == "" || o.calicoDir == "") {
		errStack = errors.Join(errStack, errors.New("hashrelease requires calico version and directory to be specified"))
	}
	if !o.validateBranch {
		return errStack
	}
	branch, err := utils.GitBranch(o.dir)
	if err != nil {
		return fmt.Errorf("failed to determine branch: %w", err)
	}
	match := fmt.Sprintf(`^(%s|%s-v\d+\.\d+(?:-\d+)?)$`, utils.DefaultBranch, o.releaseBranchPrefix)
	re := regexp.MustCompile(match)
	if !re.MatchString(branch) {
		errStack = errors.Join(errStack, fmt.Errorf("not on a release branch"))
	}
	return errStack
}

func (o *OperatorManager) PrePublishValidation() error {
	if !o.publish {
		return nil
	}
	if o.dir == "" {
		return fmt.Errorf("no repository root specified")
	}
	var errStack error
	if o.image == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator image specified"))
	}
	if o.registry == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator registry specified"))
	}
	if o.version == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no version specified"))
	}
	return errStack
}

func (o *OperatorManager) Publish() error {
	if !o.publish {
		logrus.Warn("Skipping publishing operator")
		return nil
	}

	env, logFields := o.env()
	logrus.WithFields(logFields).Info("Publishing operator")
	out, err := o.make("release-publish", env)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to publish operator: %w", err)
	}
	logrus.WithFields(logFields).Infof("Published operator: %s", out)
	return nil
}

func (o *OperatorManager) PreReleasePublicValidation() error {
	if !o.publish || !o.validate {
		return nil
	}
	var errStack error
	if o.dir == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no repository root specified"))
	}
	if o.version == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no version specified"))
	}
	return errStack
}

// ReleasePublic publishes the current draft release of the operator to make it publicly available.
// It determines the latest release version, compares it with the current version, and marks the release as the latest if applicable.
func (o *OperatorManager) ReleasePublic() error {
	if !o.publish {
		logrus.Warn("Skipping releasing operator to public")
		return nil
	}
	if err := o.PreReleasePublicValidation(); err != nil {
		return err
	}
	env := append(os.Environ(), fmt.Sprintf("VERSION=%s", o.version))
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		env = append(env, "DEBUG=true")
	}
	out, err := o.make("release-public", env)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to release operator: %w", err)
	}
	return nil
}

func (o *OperatorManager) make(target string, env []string) (string, error) {
	return o.runner.Run("make", []string{"-C", o.dir, target}, env)
}

func Clone(org, repo, branch, dir string) error {
	return utils.Clone(fmt.Sprintf("git@github.com:%s/%s.git", org, repo), branch, dir)
}
