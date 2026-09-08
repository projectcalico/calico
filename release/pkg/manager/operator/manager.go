// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.

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
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
)

const DefaultImage = registry.OperatorImage

var DefaultRegistries = registry.DefaultOperatorRegistries

var (
	defaultProductEnvPrefix = "CALICO"
	defaultProductRegistry  = registry.DefaultCalicoRegistries[0]

	// productVersionVar is the operator make variable carrying the version its component
	// images are published at.
	productVersionVar = "CALICO_VERSION"
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

	// calicoVersion is the version the Calico components the built operator deploys are
	// published at.
	calicoVersion string

	// image is the name of the operator image (e.g. operator)
	image string

	// registries are the registries the image is published to. The first names the
	// image in the pinned version file and the release output.
	registries []string

	// productRegistry is the registry to use for product images (e.g. quay.io/calico)
	productRegistry string

	// isHashRelease indicates if we are doing a hashrelease
	isHashRelease bool

	// validate indicates if we should run validation
	validate bool

	// architectures is the list of architectures for which we should build images.
	// If empty, we build for all.
	architectures []string
}

func NewManager(opts ...Option) *OperatorManager {
	o := &OperatorManager{
		runner:     &command.RealCommandRunner{},
		registries: DefaultRegistries,
		image:      DefaultImage,
		validate:   true,
	}
	for _, opt := range opts {
		if err := opt(o); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}
	if o.productRegistry == "" {
		o.productRegistry = defaultProductRegistry
	}
	if o.dir == "" && o.calicoDir != "" {
		o.dir = filepath.Join(o.calicoDir, "operator")
	}
	return o
}

func (o *OperatorManager) Build() error {
	if err := o.PreBuildValidation(); err != nil {
		return err
	}
	env, logFields := o.env()
	logFields["product_registry"] = o.productRegistry
	r, i, err := o.productRegistryParts()
	if err != nil {
		return err
	}
	logFields[fmt.Sprintf("%s_registry", strings.ToLower(defaultProductEnvPrefix))] = r
	logFields[fmt.Sprintf("%s_image_path", strings.ToLower(defaultProductEnvPrefix))] = i
	env = append(env, fmt.Sprintf("%s_REGISTRY=%s", defaultProductEnvPrefix, r))
	env = append(env, fmt.Sprintf("%s_IMAGE_PATH=%s", defaultProductEnvPrefix, i))
	// The image tags the built operator deploys are baked into its binary, so they have
	// to reach the build whether or not this is a hashrelease.
	if o.calicoVersion != "" {
		env = append(env, fmt.Sprintf("%s=%s", productVersionVar, o.calicoVersion))
		logFields["product_version"] = o.calicoVersion
	}
	logrus.WithFields(logFields).Info("Building operator")
	out, err := o.make("release-build", env)
	if err != nil {
		logrus.Error(out)
		return fmt.Errorf("failed to build operator: %w", err)
	}
	logrus.WithFields(logFields).Infof("Built operator: %s", out)
	return nil
}

func (o *OperatorManager) Registry() string {
	if len(o.registries) == 0 {
		return ""
	}
	return o.registries[0]
}

func (o *OperatorManager) env() ([]string, logrus.Fields) {
	logFields := logrus.Fields{
		"registries": o.registries,
		"image":      o.image,
		"version":    o.version,
	}
	env := append(os.Environ(),
		fmt.Sprintf("REGISTRY=%s", o.Registry()),
		fmt.Sprintf("IMAGE_NAME=%s", o.image),
		fmt.Sprintf("VERSION=%s", o.version),
		fmt.Sprintf("DEV_REGISTRIES=%s", strings.Join(o.registries, " ")),
	)
	if o.isHashRelease {
		logFields["hashrelease"] = "true"
	} else {
		env = append(env, "RELEASE=true")
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
	// Split and filter out empty parts from double slashes or trailing slashes.
	var parts []string
	for _, part := range strings.Split(o.productRegistry, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	if len(parts) < 2 {
		err = fmt.Errorf("failed to parse product registry: %s", o.productRegistry)
		return
	}
	registry = strings.Join(parts[:len(parts)-1], "/") + "/"
	imagePath = parts[len(parts)-1] + "/"
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
	if o.isHashRelease {
		if o.calicoVersion == "" {
			errStack = errors.Join(errStack, errors.New("hashrelease requires the product version to be specified"))
		}
		if o.calicoDir == "" {
			errStack = errors.Join(errStack, errors.New("hashrelease requires the calico directory to be specified"))
		}
	}
	return errStack
}

func (o *OperatorManager) PrePublishValidation() error {
	if o.dir == "" {
		return fmt.Errorf("no repository root specified")
	}
	var errStack error
	if o.image == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no operator image specified"))
	}
	if len(o.registries) == 0 {
		errStack = errors.Join(errStack, fmt.Errorf("no operator registry specified"))
	}
	if o.version == "" {
		errStack = errors.Join(errStack, fmt.Errorf("no version specified"))
	}
	return errStack
}

func (o *OperatorManager) Publish() error {
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

func (o *OperatorManager) make(target string, env []string) (string, error) {
	return o.runner.Run("make", []string{"-C", o.dir, target}, env)
}
