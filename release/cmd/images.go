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

	cli "github.com/urfave/cli/v3"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/images"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

// imagesRunner drives make; imagesDigestResolver looks up a published digest.
// Tests replace both.
var (
	imagesRunner         command.CommandRunner = &command.RealCommandRunner{}
	imagesDigestResolver images.DigestResolver = registry.ResolveDigest
)

func imagesCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "images",
		Usage: "Build and publish container images",
		Commands: []*cli.Command{
			imagesBuildCommand(cfg),
			imagesPublishCommand(cfg),
		},
	}
}

func imagesBuildCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "build",
		Usage: "Build container images",
		Flags: []cli.Flag{registryFlag, archFlag, imageReleaseDirsFlag},
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("images-build.log")
			ver, _, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}
			return images.Build(images.Config{
				RepoRoot:   cfg.RepoRootDir,
				Version:    ver.FormattedString(),
				Registries: c.StringSlice(registryFlag.Name),
				Arches:     c.StringSlice(archFlag.Name),
				Variants:   images.NarrowVariants(images.BuildVariants, c.StringSlice(imageReleaseDirsFlag.Name)),
				LogsDir:    cfg.LogsDir,
			}, images.WithRunner(imagesRunner))
		},
	}
}

func imagesPublishCommand(cfg *Config) *cli.Command {
	return &cli.Command{
		Name:  "publish",
		Usage: "Publish container images to their registries",
		Flags: append([]cli.Flag{
			registryFlag, archFlag, localFlag, imageReleaseDirsFlag,
			fromRegistryFlag, fromTagFlag, skipDevImageRetagFlag, forceFlag,
		}, imageScanFlags...),
		Action: func(_ context.Context, c *cli.Command) error {
			configureLogging("images-publish.log")
			ver, _, err := version.VersionsFromManifests(cfg.RepoRootDir)
			if err != nil {
				return err
			}
			// A narrowed run must scan only what it published.
			dirs := c.StringSlice(imageReleaseDirsFlag.Name)
			scanDirs := dirs
			if len(scanDirs) == 0 {
				scanDirs = utils.ImageDiscoveryDirs()
			}
			scan, err := scanRequest(c, cfg, scanDirs, ver.Stream(), utils.CalicoProductCode)
			if err != nil {
				return err
			}
			// An earlier run of this version records what it published, so a
			// resume skips the units already done.
			published, err := outputs.ReadRefs(cfg.OutputDir, "images-publish", ver.FormattedString())
			if err != nil {
				return err
			}

			var refs images.RefRecorder
			if !c.Bool(localFlag.Name) {
				w, err := outputs.NewRefsWriter(cfg.OutputDir, "images-publish", ver.FormattedString())
				if err != nil {
					return err
				}
				refs = w
			}
			p, err := images.NewPublisher(images.Config{
				RepoRoot:   cfg.RepoRootDir,
				Version:    ver.FormattedString(),
				Registries: c.StringSlice(registryFlag.Name),
				Arches:     c.StringSlice(archFlag.Name),
				Variants:   images.NarrowVariants(images.PublishVariants, dirs),
				Publish:    !c.Bool(localFlag.Name),
				From:       c.String(fromRegistryFlag.Name),
				FromTag:    c.String(fromTagFlag.Name),
				LogsDir:    cfg.LogsDir,
				Scan:       scan,
				Refs:       refs,
				Published:  published,
				Force:      c.Bool(forceFlag.Name),

				SkipDevImageRetag: c.Bool(skipDevImageRetagFlag.Name),
				ResolveDigest:     imagesDigestResolver,
			}, images.WithRunner(imagesRunner))
			if err != nil {
				return err
			}
			return p.Publish()
		},
	}
}

// scanRequest is the scan submission for a standalone publish, or nil when
// scanning is off. Such a publish is always a release; a hashrelease is scanned
// by the flow that built it. The image list runs make in every release
// directory, so it is resolved only when a scan is wanted.
func scanRequest(c *cli.Command, cfg *Config, dirs []string, stream, productCode string) (*images.ScanRequest, error) {
	if !c.Bool(imageScanFlag.Name) {
		return nil, nil
	}
	imgs, err := utils.BuildReleaseImageList(cfg.RepoRootDir, dirs...)
	if err != nil {
		return nil, err
	}
	return &images.ScanRequest{
		Config:      *imageScanningAPIConfig(c),
		ProductCode: productCode,
		Images:      imgs,
		Stream:      stream,
		Release:     true,
		OutputDir:   cfg.TmpDir,
	}, nil
}
