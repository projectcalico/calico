// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"path/filepath"

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/operator"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

func operatorCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "operator",
		Usage:    "Build and publish the operator",
		Commands: operatorSubCommands(cfg),
	}
}

var operatorSubCommands = func(cfg *Config) []*cli.Command {
	return []*cli.Command{
		operatorBuildCommand(cfg),
		operatorPublishCommand(cfg),
	}
}

var operatorBuildFlags = []cli.Flag{
	operatorRegistryFlag, registryFlag, archFlag,
	validationFlag, hashreleaseFlag, releaseBranchPrefixFlag,
}

var operatorBuildAction = func(cfg *Config) func(context.Context, *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("operator-build.log")
		o, err := operatorFor(cfg, c, oncePin(pinForBuild))
		if err != nil {
			return err
		}
		return operator.Build(*o, operatorVariants(c), c.Bool(hashreleaseFlag.Name),
			operatorBuildOptions(c, filepath.Join(cfg.LogsDir, o.ProductVersion))...)
	}
}

func operatorBuildCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "build",
		Usage:  "Build the operator image",
		Flags:  operatorBuildFlags,
		Action: operatorBuildAction(cfg),
	}
}

var operatorPublishFlags = []cli.Flag{
	operatorRegistryFlag, archFlag, localFlag, hashreleaseFlag,
}

var operatorPublishAction = func(cfg *Config) func(context.Context, *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("operator-publish.log")
		o, err := operatorFor(cfg, c, oncePin(pinForPublish))
		if err != nil {
			return err
		}
		opts, err := operatorPublishOptions(c, o.Version, cfg.OutputDir, filepath.Join(cfg.LogsDir, o.ProductVersion))
		if err != nil {
			return err
		}
		return operator.Publish(*o, operatorVariants(c), c.Bool(hashreleaseFlag.Name), opts...)
	}
}

func operatorPublishCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "publish",
		Usage:  "Publish the operator image to its registries",
		Flags:  operatorPublishFlags,
		Action: operatorPublishAction(cfg),
	}
}

var operatorBuildOptions = func(c *cli.Command, logsDir string) []operator.BuildOption {
	return []operator.BuildOption{
		operator.WithRunner(commandRunner),
		operator.WithLogsDir(logsDir),
		operator.WithArches(c.StringSlice(archFlag.Name)...),
		operator.WithValidation(c.Bool(validationFlag.Name)),
	}
}

var operatorPublishOptions = func(c *cli.Command, version, uploadDir, logsDir string) ([]operator.PublishOption, error) {
	opts := []operator.PublishOption{
		operator.WithRunner(commandRunner),
		operator.WithLogsDir(logsDir),
		operator.WithArches(c.StringSlice(archFlag.Name)...),
		operator.WithDryRun(c.Bool(localFlag.Name)),
	}
	_, w, err := publishRecord(uploadDir, operator.PublishStep, version, !c.Bool(localFlag.Name))
	if err != nil {
		return nil, err
	}
	if w != nil {
		opts = append(opts, operator.WithRecord(w))
	}
	return opts, nil
}

var operatorRegistries = func(c *cli.Command) []string {
	reg := c.StringSlice(operatorRegistryFlag.Name)
	if len(reg) == 0 {
		return registry.DefaultOperatorRegistries
	}
	return reg
}

var operatorVariants = func(_ *cli.Command) []operator.Variant {
	return operator.Variants()
}

// A hashrelease takes its versions from the pin, a release from the
// manifests in the tree.
var operatorFor = func(cfg *Config, c *cli.Command, pin pinned) (*operator.Operator, error) {
	if c.Bool(hashreleaseFlag.Name) {
		p, err := pin(cfg, c)
		if err != nil {
			return nil, err
		}
		o := pinnedOperator(cfg, c, p.Operator, p.ProductVersion)
		return &o, nil
	}
	return releaseOperator(cfg, c)
}

var releaseOperator = func(cfg *Config, c *cli.Command) (*operator.Operator, error) {
	ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
	if err != nil {
		return nil, err
	}
	return &operator.Operator{
		RepoRoot:        cfg.RepoRootDir,
		Version:         operatorVer.FormattedString(),
		Image:           registry.OperatorImage,
		Registries:      operatorRegistries(c),
		ProductVersion:  ver.FormattedString(),
		ProductRegistry: productRegistry(c),
	}, nil
}

var pinnedOperator = func(cfg *Config, c *cli.Command, pinned registry.Component, productVersion string) operator.Operator {
	// An explicit flag beats the pin; otherwise the pin names where the
	// hashrelease already published.
	reg := operatorRegistries(c)
	if len(c.StringSlice(operatorRegistryFlag.Name)) == 0 && pinned.Registry != "" {
		reg = []string{pinned.Registry}
	}
	img := registry.OperatorImage
	if pinned.Image != "" {
		img = pinned.Image
	}
	return operator.Operator{
		RepoRoot:        cfg.RepoRootDir,
		Version:         pinned.Version,
		Image:           img,
		Registries:      reg,
		ProductVersion:  productVersion,
		ProductRegistry: productRegistry(c),
	}
}
