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

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/utils"
)

const MutableCachePolicy = "max-age=60, s-maxage=300, stale-while-revalidate=60"

var (
	_ Handler = S3{}
	_ Handler = GCS{}
	_ Handler = HashreleaseServer{}
	_ Handler = Preparer{}
	_ Handler = Publisher{}

	_ Validator = S3{}
	_ Validator = GCS{}
	_ Validator = HashreleaseServer{}
	_ Validator = Preparer{}
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

// Create a SHA256 checksum file for all files and write it to the specified directory.
// Returns the release assets: the files checksummed, plus the sums file.
// SHA256Sums writes a checksum file covering everything at the top level of
// dir, and returns dir's files plus that file. Any existing sums file is
// replaced rather than checksummed into itself.
func SHA256Sums(dir string, opts ...Option) error {
	files, err := utils.TopLevelFiles(dir, SumsFileName)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no files to checksum in %s", dir)
	}
	_, err = sha256Sums(dir, files, opts...)
	return err
}

func sha256Sums(dir string, files []string, opts ...Option) ([]string, error) {
	s, err := newSettings(sumsStep, opts)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, SumsFileName)
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
	out, err := s.Runner().Run("sha256sum", names, command.WithDir(dir))
	if err != nil {
		return nil, s.Errorf("checksumming files: %w", err)
	}
	if err := os.WriteFile(path, []byte(out), filePerms); err != nil {
		return nil, s.Errorf("writing %s: %w", path, err)
	}
	s.Logger().WithField("files", len(files)).Info("Wrote checksums")
	return append(files, path), nil
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

func (d HashreleaseServer) Artifacts(src string) ([]outputs.ArtifactFile, error) {
	return outputs.ArtifactsAt(src, d.Release.URL(), SumsFileName)
}

func (d HashreleaseServer) Validate(u Upload) error {
	return validSource(u)
}

// Publisher adapts a group's own publish to the Handler interface,
type Publisher = Preparer

type Preparer struct {
	Kind string

	Action func() error
	Check  func() error
}

func (d Preparer) Name() string { return d.Kind }

func (d Preparer) Validate(Upload) error {
	if d.Check == nil {
		return nil
	}
	return d.Check()
}

func (d Preparer) Publish(context.Context, string) error { return d.Action() }

func validSource(u Upload) error {
	if u.Source == "" {
		return fmt.Errorf("upload to %s has no source", u.Handler.Name())
	}
	return nil
}
