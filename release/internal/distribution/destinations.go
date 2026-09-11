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

package distribution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/steps"
)

const (
	gcloudCmd = "gcloud"
	awsCmd    = "aws"

	cpVerb    = "cp"
	syncVerb  = "sync"
	rsyncVerb = "rsync"

	recursiveFlag = "--recursive"
)

var publicRead = []string{"--acl", "public-read"}

var (
	_ Destination = S3{}
	_ Destination = GCS{}
	_ Destination = GithubRelease{}
)

type S3 struct {
	URI string

	Sync bool

	Profile string

	Private bool

	DryRun bool

	Runner command.CommandRunner
}

func (d S3) Name() string { return d.URI }

func (d S3) Publish(_ context.Context, src string) error {
	args := []string{"s3"}
	if d.Profile != "" {
		args = append(args, "--profile", d.Profile)
	}
	verFn := d.cpArgs
	if d.Sync {
		verFn = d.syncArgs
	}
	verbArgs, err := verFn(src)
	if err != nil {
		return fmt.Errorf("action verb: %w", err)
	}
	args = append(args, verbArgs...)
	args = append(args, src, d.URI)
	if !d.Private {
		args = append(args, publicRead...)
	}
	if d.DryRun {
		args = append(args, "--dryrun")
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	logrus.WithField("args", args).Debug("Running aws command")
	if _, err := d.runner().Run(awsCmd, args, nil); err != nil {
		return fmt.Errorf("publish to %s:%w", d.Name(), err)
	}
	return nil
}

func (d S3) cpArgs(src string) ([]string, error) {
	if d.Sync {
		return d.syncArgs(src)
	}
	args := []string{cpVerb}
	dir, err := isDir(src)
	if err != nil {
		return args, fmt.Errorf("isDir(%s): %w", src, err)
	}
	if dir {
		args = append(args, recursiveFlag)
	}
	return args, nil
}

func (d S3) syncArgs(src string) ([]string, error) {
	if !d.Sync {
		return d.cpArgs(src)
	}
	// sync descends on its own, and the CLI rejects --recursive alongside it.
	return []string{syncVerb}, nil
}

func (d S3) runner() command.CommandRunner {
	if d.Runner == nil {
		return &command.RealCommandRunner{}
	}
	return d.Runner
}

type GCS struct {
	URI string

	Sync bool

	DryRun bool

	Runner command.CommandRunner
}

func (d GCS) Name() string { return d.URI }

func (d GCS) Publish(_ context.Context, src string) error {
	verbFn := d.cpArgs
	if d.Sync {
		verbFn = d.rsyncArgs
	}
	verbArgs, err := verbFn(src)
	if err != nil {
		return fmt.Errorf("action verb: %w", err)
	}
	args := append(slices.Clone(verbArgs), src, d.URI)
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbosity=debug")
	}
	// gcloud storage has no dry-run flag, so the run has to be skipped.
	if d.DryRun {
		logrus.WithField("args", args).Info("Dry run, not uploading")
		return nil
	}

	if _, err := d.runner().Run(gcloudCmd, args, nil); err != nil {
		logrus.WithField("args", args).Debug("Running gcloud command")
		return fmt.Errorf("publishing to %s: %w", d.URI, err)
	}
	return nil
}

func (d GCS) cpArgs(src string) ([]string, error) {
	if d.Sync {
		return d.rsyncArgs(src)
	}
	args := []string{cpVerb}
	if d.DryRun {
		args = []string{rsyncVerb}
	}
	dir, err := isDir(src)
	if err != nil {
		return nil, err
	}
	if dir || d.DryRun {
		args = append(args, "--recursive")
	}
	return args, nil
}

func (d GCS) rsyncArgs(src string) ([]string, error) {
	if !d.Sync {
		return d.cpArgs(src)
	}
	args := []string{rsyncVerb, "--recursive", "--delete-unmatched-destination-objects"}

	if d.DryRun {
		args = append(args, "--dry-run")
	}
	return args, nil
}

func (d GCS) runner() command.CommandRunner {
	if d.Runner == nil {
		return &command.RealCommandRunner{}
	}
	return d.Runner
}

type GithubRelease struct {
	Releases *github.Releases

	Tag   string
	Title string
	Body  string

	Draft  bool
	DryRun bool

	Log *logrus.Entry
}

func (d GithubRelease) Name() string { return fmt.Sprintf("%s github release", d.Tag) }

func (d GithubRelease) Publish(ctx context.Context, src string) error {
	files, err := topLevelFiles(src)
	if err != nil {
		return fmt.Errorf("get files: %w", err)
	}
	if len(files) == 0 {
		return fmt.Errorf("no release files %s", d.Tag)
	}
	if d.DryRun {
		d.log().WithField("files", files).Infof("Dry run, not creating %s", d.Name())
		return nil
	}

	rel, err := d.Releases.CreateDraft(ctx, d.Tag, d.releaseName(), d.Body)
	if err != nil {
		return fmt.Errorf("create draft: %w", err)
	}

	// Collected rather than stopped at: one asset failing must not hide the
	// rest, and a retry needs to know everything still outstanding.
	_, err = steps.Go(files, func(path string) (struct{}, error) {
		return struct{}{}, d.upload(ctx, rel.GetID(), path)
	})
	if err != nil {
		return fmt.Errorf("upload assets: %w", err)
	}
	if d.Draft {
		return nil
	}
	latest, err := d.makeLatest(ctx)
	if err != nil {
		return fmt.Errorf("make latest: %w", err)
	}
	return d.Releases.Publish(ctx, d.Tag, latest)
}

func (d GithubRelease) makeLatest(ctx context.Context) (bool, error) {
	latest, err := d.Releases.LatestTag(ctx)
	if err != nil {
		return false, fmt.Errorf("get latest tag: %w", err)
	}
	curr, err := d.semver(latest)
	if err != nil {
		return false, fmt.Errorf("parse current tag: %w", err)
	}
	new, err := d.semver(d.Tag)
	if err != nil {
		return false, fmt.Errorf("parse latest tag: %w", err)
	}
	return new.GreaterThan(curr), nil
}

func (d GithubRelease) semver(tag string) (*semver.Version, error) {
	return semver.NewVersion(strings.Trim(tag, "v"))
}

func (d GithubRelease) upload(ctx context.Context, releaseID int64, path string) error {
	log := d.log().WithField("asset", filepath.Base(path))
	for attempt := 0; ; attempt++ {
		err := d.Releases.UploadAsset(ctx, releaseID, path)
		if err == nil {
			log.Debug("Attached release asset")
			return nil
		}
		if attempt < steps.MaxRetries {
			log.WithError(err).WithField("attempt", attempt).Warn("Asset upload failed, retrying")
			continue
		}
		return fmt.Errorf("upload %s: %w", path, err)
	}
}

func (d GithubRelease) releaseName() string {
	if d.Title == "" {
		return d.Tag
	}
	return d.Title
}

func (d GithubRelease) log() *logrus.Entry {
	if d.Log == nil {
		return logrus.NewEntry(logrus.StandardLogger())
	}
	return d.Log
}

func topLevelFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out, nil
}

func isDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}
