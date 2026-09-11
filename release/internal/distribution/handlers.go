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
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
)

const (
	gcloudCmd = "gcloud"
	awsCmd    = "aws"

	s3Cmd      = "s3"
	storageCmd = "storage"

	cpVerb    = "cp"
	syncVerb  = "sync"
	rsyncVerb = "rsync"

	recursiveFlag = "--recursive"
)

var publicRead = []string{"--acl", "public-read"}

var (
	_ Handler = S3{}
	_ Handler = GCS{}
	_ Handler = GithubRelease{}
	_ Handler = HashreleaseServer{}
	_ Handler = Preparer{}
	_ Handler = Publisher{}

	_ validator = S3{}
	_ validator = GCS{}
	_ validator = GithubRelease{}
	_ validator = HashreleaseServer{}
)

// paths is what cloud bucket handlers need to know.
type paths struct {
	src  string
	dest string
	dir  bool
}

func newPaths(src, dest string) (paths, error) {
	dir, err := utils.DirExists(src)
	if err != nil {
		return paths{}, fmt.Errorf("reading %s: %w", src, err)
	}
	return paths{src: src, dest: dest, dir: dir}, nil
}

func (p paths) run(r command.CommandRunner, name string, args []string) error {
	if r == nil {
		r = &command.RealCommandRunner{}
	}
	logrus.WithField("args", args).Debugf("Running %s command", name)
	if _, err := r.Run(name, args, nil); err != nil {
		return fmt.Errorf("copying to %s: %w", p.dest, err)
	}
	return nil
}

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
	p, err := newPaths(src, d.URI)
	if err != nil {
		return err
	}
	// A destination without the slash names one object rather than a prefix,
	// so a directory upload would collapse into a single file.
	if p.dir {
		p.src, p.dest = addTrailingSlash(p.src), addTrailingSlash(p.dest)
	}

	args := []string{s3Cmd}
	if d.Profile != "" {
		args = append(args, "--profile", d.Profile)
	}
	if d.Sync {
		// sync descends on its own, and the CLI rejects --recursive with it.
		args = append(args, syncVerb)
	} else {
		args = append(args, cpVerb)
		if p.dir {
			args = append(args, recursiveFlag)
		}
	}
	args = append(args, p.src, p.dest)
	if !d.Private {
		args = append(args, publicRead...)
	}
	if d.DryRun {
		args = append(args, "--dryrun")
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--debug")
	}
	err = p.run(d.Runner, awsCmd, args)
	if err != nil {
		return fmt.Errorf("%s %s: %w", awsCmd, s3Cmd, err)
	}
	return nil
}

func (d S3) Validate(u Upload) error {
	return validSource(u)
}

func addTrailingSlash(s string) string {
	if !strings.HasSuffix(s, "/") {
		return s + "/"
	}
	return s
}

type GCS struct {
	URI string

	Sync bool

	DryRun bool

	Runner command.CommandRunner
}

func (d GCS) Name() string { return d.URI }

func (d GCS) Publish(_ context.Context, src string) error {
	p, err := newPaths(src, d.URI)
	if err != nil {
		return err
	}

	// cp has no dry run of its own, so a preview uses rsync for both.
	args := []string{storageCmd, cpVerb}
	switch {
	case d.Sync:
		args = []string{storageCmd, rsyncVerb, recursiveFlag, "--delete-unmatched-destination-objects"}
	case d.DryRun:
		args = []string{storageCmd, rsyncVerb, recursiveFlag}
	case p.dir:
		args = append(args, recursiveFlag)
	}
	if d.DryRun {
		args = append(args, "--dry-run")
	}
	args = append(args, p.src, p.dest)
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		args = append(args, "--verbosity=debug")
	}
	err = p.run(d.Runner, gcloudCmd, args)
	if err != nil {
		return fmt.Errorf("%s %s: %w", gcloudCmd, storageCmd, err)
	}
	return nil
}

func (d GCS) Validate(u Upload) error {
	return validSource(u)
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
	latestTag, err := d.Releases.LatestTag(ctx)
	if err != nil {
		return false, fmt.Errorf("get latest tag: %w", err)
	}
	// Nothing published yet, so this release is the latest by default.
	if latestTag == "" {
		return true, nil
	}
	latest, err := d.semver(latestTag)
	if err != nil {
		return false, fmt.Errorf("parse latest tag %q: %w", latestTag, err)
	}
	this, err := d.semver(d.Tag)
	if err != nil {
		return false, fmt.Errorf("parse release tag %q: %w", d.Tag, err)
	}
	return this.GreaterThan(latest), nil
}

func (d GithubRelease) semver(tag string) (*semver.Version, error) {
	return semver.NewVersion(strings.TrimPrefix(tag, "v"))
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

func (d GithubRelease) Validate(u Upload) error {
	return validSource(u)
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

// Hashrelease uploads the whole output tree, then records the hashrelease in
// the server's library.
type HashreleaseServer struct {
	Release *hashreleaseserver.Hashrelease

	Config *hashreleaseserver.Config

	ProductCode string

	DryRun bool

	Runner command.CommandRunner
}

func (d HashreleaseServer) Name() string { return fmt.Sprintf("%s hashrelease", d.Release.Name) }

func (d HashreleaseServer) Publish(ctx context.Context, src string) error {
	bucket := GCS{
		URI:    d.Release.BucketURI(d.Config),
		Sync:   true,
		DryRun: d.DryRun,
		Runner: d.Runner,
	}
	if err := bucket.Publish(ctx, src); err != nil {
		return err
	}
	if d.DryRun {
		logrus.WithField("hashrelease", d.Release.Name).Info("Dry run, not recording hashrelease")
		return nil
	}
	return hashreleaseserver.Record(d.ProductCode, d.Release, d.Config)
}

func (d HashreleaseServer) Validate(u Upload) error {
	return validSource(u)
}

// Publisher adapts a group's own publish to the Handler interface,
type Publisher = Preparer

type Preparer struct {
	Kind string

	Action func() error
}

func (d Preparer) Name() string { return d.Kind }

func (d Preparer) Publish(context.Context, string) error { return d.Action() }

func validSource(u Upload) error {
	if u.Source == "" {
		return fmt.Errorf("upload to %s has no source", u.Handler.Name())
	}
	return nil
}
