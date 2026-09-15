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

	"github.com/projectcalico/calico/release/internal/charts"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

func chartsCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "charts",
		Usage: "Build and publish Helm charts",
		Commands: []*cli.Command{
			chartsBuildCommand(cfg),
			chartsPublishCommand(cfg),
		},
	}
}

var chartsBuildFlags = []cli.Flag{
	registryFlag, operatorRegistryFlag, operatorImageFlag,
	helmIndexFlag(envBuildHelmIndex), hashreleaseFlag, releaseBranchPrefixFlag,
}

var chartsBuildAction = func(cfg *Config) func(context.Context, *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("charts-build.log")
		pin := oncePin(pinForBuild)
		chart, err := pinnedChart(cfg, c, pin)
		if err != nil {
			return err
		}
		opts, err := chartsBuildOptions(cfg, c, *chart, pin, c.Bool(helmIndexFlagName))
		if err != nil {
			return err
		}
		opts = append(opts, charts.WithRunner(commandRunner), charts.WithLogsDir(cfg.LogsDir))
		return charts.Build(*chart, opts...)
	}
}

func chartsBuildCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "build",
		Usage:  "Build Helm charts",
		Flags:  chartsBuildFlags,
		Action: chartsBuildAction(cfg),
	}
}

var chartsPublishFlags = []cli.Flag{helmRegistryFlag, localFlag, forceFlag, hashreleaseFlag}

var chartsPublishAction = func(cfg *Config) func(context.Context, *cli.Command) error {
	return func(_ context.Context, c *cli.Command) error {
		configureLogging("charts-publish.log")
		chart, err := pinnedChart(cfg, c, pinForPublish)
		if err != nil {
			return err
		}
		registries := c.StringSlice(helmRegistryFlag.Name)
		if len(registries) == 0 {
			registries = registry.DefaultHelmRegistries
		}
		confirm := !c.Bool(localFlag.Name)

		opts := []charts.PublishOption{
			charts.WithRunner(commandRunner),
			charts.WithLogsDir(cfg.LogsDir),
			charts.WithResolver(registryDigestResolver),
		}
		published, w, err := publishRecord(cfg, charts.PublishStep, chart.Version(), confirm)
		if err != nil {
			return err
		}
		opts = append(opts, charts.WithResume(published, c.Bool(forceFlag.Name)))
		if w != nil {
			opts = append(opts, charts.WithRecord(w))
		}
		return charts.Publish(*chart, registries, confirm, opts...)
	}
}

func chartsPublishCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:   "publish",
		Usage:  "Publish Helm charts to their registries",
		Flags:  chartsPublishFlags,
		Action: chartsPublishAction(cfg),
	}
}

var pinnedChart = func(cfg *Config, c *cli.Command, pin pinned) (*charts.Chart, error) {
	if c.Bool(hashreleaseFlag.Name) {
		p, err := pin(cfg, c)
		if err != nil {
			return nil, err
		}
		return &charts.Chart{
			RepoRoot:       cfg.RepoRootDir,
			ProductVersion: p.ProductVersion,
			ChartVersion:   p.ChartVersion,
			Names:          charts.All(),
			BaseDir:        charts.Dir(p.Hashrelease(baseHashreleaseOutputDir(cfg.RepoRootDir), false).Source),
		}, nil
	}
	ver, _, err := version.VersionsFromManifests(cfg.RepoRootDir)
	if err != nil {
		return nil, err
	}
	return &charts.Chart{
		RepoRoot:       cfg.RepoRootDir,
		ProductVersion: ver.FormattedString(),
		Names:          charts.All(),
		BaseDir:        charts.Dir(filepath.Join(cfg.OutputDir, ver.FormattedString())),
	}, nil
}

// chartsBuildOptions are the settings a build needs beyond the charts
// themselves. A hashrelease pins its own versions and serves its own charts.
var chartsBuildOptions = func(cfg *Config, c *cli.Command, chart charts.Chart, pin pinned, withIndex bool) ([]charts.BuildOption, error) {
	var opts []charts.BuildOption
	chartURL, err := charts.ChartsURL(chart)
	if err != nil {
		return nil, err
	}
	if c.Bool(hashreleaseFlag.Name) {
		p, err := pin(cfg, c)
		if err != nil {
			return nil, err
		}
		opts = append(opts, charts.WithModifiedValues(charts.ValueEditsFor(p.ProductVersion, p.ProductRegistry, p.Operator.Image, p.Operator.Version, p.Operator.Registry)))
		chartURL = hashreleaseserver.HashreleaseURL(p.ReleaseName)
	}
	if withIndex {
		repoURL, err := charts.RepoURL()
		if err != nil {
			return nil, err
		}
		opts = append(opts, charts.WithIndex(repoURL, chartURL, chart.BaseDir, cfg.TmpDir))
	}
	return opts, nil
}
