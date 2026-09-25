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

	"github.com/projectcalico/calico/release/internal/manifests"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

func manifestsCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:     "manifests",
		Usage:    "Build the manifests",
		Commands: manifestsSubcommands(cfg),
	}
}

var manifestsSubcommands = func(cfg *Config) []*cli.Command {
	return []*cli.Command{
		manifestsBuildCommand(cfg),
	}
}

var manifestsBuildFlags = []cli.Flag{
	registryFlag, operatorRegistryFlag,
	ocpBundleFlag, hashreleaseFlag, releaseBranchPrefixFlag,
}

var manifestsBuildAction = func(cfg *Config) func(context.Context, *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("manifests-build.log")
		m, err := pinnedManifests(cfg, c, oncePin(pinForBuild))
		if err != nil {
			return err
		}
		return manifests.Build(*m, true, c.Bool(ocpBundleFlag.Name),
			manifests.WithRunner(commandRunner), manifests.WithLogsDir(cfg.LogsDir),
			manifests.WithCollect())
	}
}

func manifestsBuildCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "build",
		Usage:  "Build the Kubernetes manifests",
		Flags:  manifestsBuildFlags,
		Action: manifestsBuildAction(cfg),
	}
}

func firstRegistry(c *cli.Command) string {
	if reg := c.StringSlice(registryFlag.Name); len(reg) > 0 {
		return reg[0]
	}
	return ""
}

// A hashrelease takes its versions from the pin; a release reads them back out
// of the manifests already in the tree.
var pinnedManifests = func(cfg *Config, c *cli.Command, pin pinned) (*manifests.Manifests, error) {
	if c.Bool(hashreleaseFlag.Name) {
		p, err := pin(cfg, c)
		if err != nil {
			return nil, err
		}
		return &manifests.Manifests{
			RepoRoot:  cfg.RepoRootDir,
			Version:   p.ProductVersion,
			Operator:  p.Operator,
			Registry:  p.ProductRegistry,
			OutputDir: p.Hashrelease(baseHashreleaseOutputDir(cfg.RepoRootDir), false).Source,
		}, nil
	}
	ver, operatorVer, err := version.VersionsFromManifests(cfg.RepoRootDir)
	if err != nil {
		return nil, err
	}
	return &manifests.Manifests{
		RepoRoot: cfg.RepoRootDir,
		Version:  ver.FormattedString(),
		Operator: registry.Component{
			Version:  operatorVer.FormattedString(),
			Image:    registry.OperatorImage,
			Registry: operatorRegistries(c)[0],
		},
		Registry:  firstRegistry(c),
		OutputDir: filepath.Join(cfg.OutputDir, ver.FormattedString()),
	}, nil
}
