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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/Masterminds/semver/v3"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/github"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/steps"
)

const MutableCachePolicy = "max-age=60, s-maxage=300, stale-while-revalidate=60"

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

type S3 struct {
	URI string

	Sync bool

	Profile string

	// Credentials, when set, are used alone: no env var or shared config is read.
	Credentials aws.CredentialsProvider

	Private bool

	DryRun bool

	CachePolicy string // Caching behaviour for the uploaded objects.

	Exclude []string // Pattern matching for files or objects to exclude
	Include []string // Pattern matching for files or objects to include.

	store objectStore
}

func (d S3) Name() string { return d.URI }

func (d S3) Publish(ctx context.Context, src string) error {
	// A dry-run copy reads nothing remote, so it needs no client or credentials.
	t, key, err := d.transfer(ctx, d.DryRun && !d.Sync)
	if err != nil {
		return err
	}
	if err := t.upload(ctx, src, key); err != nil {
		return fmt.Errorf("copying to %s: %w", d.URI, err)
	}
	return nil
}

// Fetch copies the tree under URI, or the one object it names, to dest.
func (d S3) Fetch(ctx context.Context, dest string) error {
	t, key, err := d.transfer(ctx, false)
	if err != nil {
		return err
	}
	if err := t.fetch(ctx, key, dest); err != nil {
		return fmt.Errorf("copying from %s: %w", d.URI, err)
	}
	return nil
}

func (d S3) transfer(ctx context.Context, offline bool) (transfer, string, error) {
	bucket, key, err := bucketURI(d.URI, "s3")
	if err != nil {
		return transfer{}, "", err
	}
	rules, err := filterRules(d.Exclude, d.Include)
	if err != nil {
		return transfer{}, "", err
	}
	store := d.store
	if store == nil && !offline {
		if store, err = newS3Store(ctx, bucket, d); err != nil {
			return transfer{}, "", fmt.Errorf("%s: %w", d.URI, err)
		}
	}
	return transfer{store: store, sync: d.Sync, dryRun: d.DryRun, rules: rules, differs: newerOrResized}, key, nil
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

	// Sync mirrors the source, deleting objects it no longer has.
	Sync bool

	DryRun bool

	store objectStore
}

func (d GCS) Name() string { return d.URI }

func (d GCS) Publish(ctx context.Context, src string) error {
	t, key, done, err := d.transfer(ctx, d.DryRun && !d.Sync)
	if err != nil {
		return err
	}
	defer done()
	if err := t.upload(ctx, src, key); err != nil {
		return fmt.Errorf("copying to %s: %w", d.URI, err)
	}
	return nil
}

// Fetch copies the tree under URI, or the one object it names, to dest.
func (d GCS) Fetch(ctx context.Context, dest string) error {
	t, key, done, err := d.transfer(ctx, false)
	if err != nil {
		return err
	}
	defer done()
	if err := t.fetch(ctx, key, dest); err != nil {
		return fmt.Errorf("copying from %s: %w", d.URI, err)
	}
	return nil
}

func (d GCS) transfer(ctx context.Context, offline bool) (transfer, string, func(), error) {
	bucket, key, err := bucketURI(d.URI, "gs")
	if err != nil {
		return transfer{}, "", nil, err
	}
	store, done := d.store, func() {}
	if store == nil && !offline {
		client, err := storage.NewClient(ctx)
		if err != nil {
			return transfer{}, "", nil, fmt.Errorf("%s: storage client: %w", d.URI, err)
		}
		store, done = gcsStore{bucket: client.Bucket(bucket)}, func() { _ = client.Close() }
	}
	return transfer{store: store, sync: d.Sync, mirror: d.Sync, dryRun: d.DryRun, differs: contentDiffers}, key, done, nil
}

func (d GCS) Validate(u Upload) error {
	return validSource(u)
}

type GithubRelease struct {
	Repo  github.Repo
	Tag   string
	Title string
	Body  string

	Draft  bool
	DryRun bool

	Log *logrus.Entry

	releases *github.Releases
}

func (d GithubRelease) Name() string { return fmt.Sprintf("%s github release", d.Tag) }

func (d GithubRelease) github() (*github.Releases, error) {
	if d.releases != nil {
		return d.releases, nil
	}
	return github.NewReleases(d.Repo, nil)
}

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
	// Written by an earlier step, and excluded from the listing so a re-run
	// does not checksum it into itself.
	sums := filepath.Join(src, sumsFileName)
	if _, err := os.Stat(sums); err != nil {
		return fmt.Errorf("%s: %w", sumsFileName, err)
	}
	files = append(files, sums)
	gh, err := d.github()
	if err != nil {
		return fmt.Errorf("github client: %w", err)
	}
	rel, err := gh.CreateDraft(ctx, d.Tag, d.releaseName(), d.Body)
	if err != nil {
		return fmt.Errorf("create draft: %w", err)
	}

	assets, err := steps.Go(files, github.NewAsset)
	if err != nil {
		return fmt.Errorf("release assets: %w", err)
	}
	missing, err := gh.SyncAssets(ctx, rel.GetID(), assets)
	if err != nil {
		return fmt.Errorf("check existing assets: %w", err)
	}
	d.log().WithFields(logrus.Fields{"upload": len(missing), "attached": len(files) - len(missing)}).Info("Release assets")

	_, err = steps.GoLimit(missing, steps.MaxConcurrency, func(a github.Asset) (struct{}, error) {
		return struct{}{}, d.upload(ctx, gh, rel.GetID(), a)
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
	return gh.Publish(ctx, d.Tag, latest)
}

func (d GithubRelease) artifacts(src string) ([]outputs.ArtifactFile, error) {
	base, err := github.DownloadURL(d.Repo.Org, d.Repo.Name, d.Tag)
	if err != nil {
		return nil, fmt.Errorf("download URL: %w", err)
	}
	return filesAt(src, base)
}

func (d GithubRelease) makeLatest(ctx context.Context) (bool, error) {
	gh, err := d.github()
	if err != nil {
		return false, fmt.Errorf("github client: %w", err)
	}
	latestTag, err := gh.LatestTag(ctx)
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

func (d GithubRelease) upload(ctx context.Context, gh *github.Releases, releaseID int64, a github.Asset) error {
	log := d.log().WithField("asset", a.Name())
	for attempt := 0; ; attempt++ {
		err := gh.UploadAsset(ctx, releaseID, a.Path)
		if err == nil {
			log.Debug("Attached release asset")
			return nil
		}
		if attempt >= steps.MaxRetries {
			return fmt.Errorf("upload %s: %w", a.Path, err)
		}
		log.WithError(err).WithField("attempt", attempt).Warn("Asset upload failed, retrying")
		// The failure may have been a lost response rather than a lost
		// upload, which would leave the name taken and reject the retry.
		complete, stateErr := gh.AssetState(ctx, releaseID, a)
		if stateErr != nil {
			return fmt.Errorf("upload %s: %w", a.Path, errors.Join(err, stateErr))
		}
		if complete {
			log.Debug("Asset already landed")
			return nil
		}
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

// Create a SHA256 checksum file for all files and write it to the specified directory.
// Returns the release assets: the files checksummed, plus the sums file.
// SHA256Sums writes a checksum file covering everything at the top level of
// dir, and returns dir's files plus that file. Any existing sums file is
// replaced rather than checksummed into itself.
func SHA256Sums(dir string) error {
	files, err := topLevelFiles(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files to checksum in %s", dir)
	}
	_, err = sha256Sums(dir, files)
	return err
}

func sha256Sums(dir string, files []string) ([]string, error) {
	s, err := newSettings(sumsStep, nil)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, sumsFileName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, s.Errorf("removing %s: %w", path, err)
	}
	if len(files) == 0 {
		return nil, s.Errorf("no files to checksum")
	}
	// names are relative to dir so the file verifies wherever the assets land.
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = filepath.Base(f)
	}
	out, err := s.Runner().RunInDir(dir, "sha256sum", names, nil)
	if err != nil {
		s.Logger().Error(out)
		return nil, s.Errorf("checksumming files: %w", err)
	}
	if err := os.WriteFile(path, []byte(out), filePerms); err != nil {
		return nil, s.Errorf("writing %s: %w", path, err)
	}
	s.Logger().WithField("files", len(files)).Info("Wrote checksums")
	return append(files, path), nil
}

func filesAt(dir, baseURL string) ([]outputs.ArtifactFile, error) {
	paths, err := topLevelFiles(dir)
	if err != nil {
		return nil, err
	}
	files := make([]outputs.ArtifactFile, len(paths))
	for i, path := range paths {
		u, err := url.JoinPath(baseURL, filepath.Base(path))
		if err != nil {
			return nil, fmt.Errorf("url for %s: %w", path, err)
		}
		files[i] = outputs.ArtifactFile{Name: filepath.Base(path), Path: path, URL: u}
	}
	return files, nil
}

func topLevelFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		// The sums file is not a release artifact in its own right: it must
		// never be checksummed into itself, and its caller adds it back.
		if e.IsDir() || e.Name() == sumsFileName {
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
}

func (d HashreleaseServer) Name() string { return fmt.Sprintf("%s hashrelease", d.Release.Name) }

func (d HashreleaseServer) Publish(ctx context.Context, src string) error {
	bucket := GCS{
		URI:    d.Release.BucketURI(d.Config),
		Sync:   true,
		DryRun: d.DryRun,
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

func (d HashreleaseServer) artifacts(src string) ([]outputs.ArtifactFile, error) {
	return filesAt(src, d.Release.URL())
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
