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

package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v53/github"
)

type Repo struct {
	Org  string
	Name string
}

func (r Repo) validate() error {
	var errs []error
	if r.Org == "" {
		errs = append(errs, fmt.Errorf("no github organization specified"))
	}
	if r.Name == "" {
		errs = append(errs, fmt.Errorf("no github repository specified"))
	}
	return errors.Join(errs...)
}

func (r Repo) String() string {
	return r.Org + "/" + r.Name
}

// Releases reads and writes a repository's GitHub releases.
type Releases struct {
	repo Repo
	svc  ReleaseService
}

// ReleaseService is the part of the GitHub releases API a release uses.
type ReleaseService interface {
	GetReleaseByTag(ctx context.Context, owner, repo, tag string) (*github.RepositoryRelease, *github.Response, error)
	CreateRelease(ctx context.Context, owner, repo string, release *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error)
	EditRelease(ctx context.Context, owner, repo string, id int64, release *github.RepositoryRelease) (*github.RepositoryRelease, *github.Response, error)
	ListReleases(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.RepositoryRelease, *github.Response, error)
	GetLatestRelease(ctx context.Context, owner, repo string) (*github.RepositoryRelease, *github.Response, error)
	ListReleaseAssets(ctx context.Context, owner, repo string, id int64, opts *github.ListOptions) ([]*github.ReleaseAsset, *github.Response, error)
	DeleteReleaseAsset(ctx context.Context, owner, repo string, id int64) (*github.Response, error)
	UploadReleaseAsset(ctx context.Context, owner, repo string, id int64, opts *github.UploadOptions, file *os.File) (*github.ReleaseAsset, *github.Response, error)
}

func NewReleases(repo Repo, svc ReleaseService) (*Releases, error) {
	if err := repo.validate(); err != nil {
		return nil, err
	}
	if svc != nil {
		return &Releases{repo: repo, svc: svc}, nil
	}
	cli, err := githubClient()
	if err != nil {
		return nil, fmt.Errorf("github client: %w", err)
	}
	return &Releases{repo: repo, svc: cli.Repositories}, nil
}

func githubToken() (string, error) {
	for _, key := range tokenEnvVars {
		if v := os.Getenv(key); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("not found. checked environment variables %s", strings.Join(tokenEnvVars, " or "))
}

func githubClient() (*github.Client, error) {
	token, err := githubToken()
	if err != nil {
		return nil, fmt.Errorf("github token: %w", err)
	}
	return github.NewTokenClient(context.Background(), token), nil
}

// Get returns the release for a tag. exists is false with a nil error when no
// release carries the tag.
func (r *Releases) Get(ctx context.Context, tag string) (*github.RepositoryRelease, bool, error) {
	rel, resp, err := r.svc.GetReleaseByTag(ctx, r.repo.Org, r.repo.Name, tag)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reading %s release %s: %w", r.repo, tag, err)
	}
	return rel, true, nil
}

// CreateDraft creates a draft release for a tag, returning the existing one if
// a draft already carries it. A published release is an error: a release
// nobody can unpublish must not be modified.
func (r *Releases) CreateDraft(ctx context.Context, tag, name, body string) (*github.RepositoryRelease, error) {
	switch existing, found, err := r.forTag(ctx, tag); {
	case err != nil:
		return nil, err
	case found && !existing.GetDraft():
		return nil, fmt.Errorf("%s release %s is already published; refusing to modify it", r.repo, tag)
	case found:
		return existing, nil
	}

	rel, _, err := r.svc.CreateRelease(ctx, r.repo.Org, r.repo.Name, &github.RepositoryRelease{
		TagName: github.String(tag),
		Name:    github.String(name),
		Body:    github.String(body),
		Draft:   github.Bool(true),
	})
	if err != nil {
		return nil, fmt.Errorf("creating %s release %s: %w", r.repo, tag, err)
	}
	return rel, nil
}

// UploadAsset attaches one file, replacing an asset of the same name. GitHub
// rejects a duplicate name, so a re-run has to delete before it uploads.
func (r *Releases) UploadAsset(ctx context.Context, releaseID int64, path string) error {
	name := filepath.Base(path)
	if err := r.deleteAsset(ctx, releaseID, name); err != nil {
		return err
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if _, _, err := r.svc.UploadReleaseAsset(ctx, r.repo.Org, r.repo.Name, releaseID,
		&github.UploadOptions{Name: name}, f); err != nil {
		return fmt.Errorf("uploading %s: %w", name, err)
	}
	return nil
}

func (r *Releases) deleteAsset(ctx context.Context, releaseID int64, name string) error {
	assets, err := r.assets(ctx, releaseID)
	if err != nil {
		return err
	}
	for _, a := range assets {
		if a.GetName() != name {
			continue
		}
		if _, err := r.svc.DeleteReleaseAsset(ctx, r.repo.Org, r.repo.Name, a.GetID()); err != nil {
			return fmt.Errorf("replacing asset %s: %w", name, err)
		}
	}
	return nil
}

func (r *Releases) assets(ctx context.Context, releaseID int64) ([]*github.ReleaseAsset, error) {
	var out []*github.ReleaseAsset
	opts := &github.ListOptions{PerPage: pageSize}
	for {
		page, resp, err := r.svc.ListReleaseAssets(ctx, r.repo.Org, r.repo.Name, releaseID, opts)
		if err != nil {
			return nil, fmt.Errorf("listing assets of %s release %d: %w", r.repo, releaseID, err)
		}
		out = append(out, page...)
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

// A draft has no git tag, so the by-tag endpoint 404s and only a listing
// finds it.
func (r *Releases) forTag(ctx context.Context, tag string) (*github.RepositoryRelease, bool, error) {
	if rel, found, err := r.Get(ctx, tag); err != nil || found {
		return rel, found, err
	}
	opts := &github.ListOptions{PerPage: pageSize}
	for {
		page, resp, err := r.svc.ListReleases(ctx, r.repo.Org, r.repo.Name, opts)
		if err != nil {
			return nil, false, fmt.Errorf("listing %s releases: %w", r.repo, err)
		}
		for _, rel := range page {
			if rel.GetTagName() == tag {
				return rel, true, nil
			}
		}
		if resp == nil || resp.NextPage == 0 {
			return nil, false, nil
		}
		opts.Page = resp.NextPage
	}
}

// Publish takes a draft live. It marks the release latest only when its
// version is the newest published one, which the caller decides.
func (r *Releases) Publish(ctx context.Context, tag string, latest bool) error {
	// forTag rather than Get: what is being published is a draft, and a draft
	// carries no git tag for the by-tag endpoint to find.
	rel, found, err := r.forTag(ctx, tag)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no %s release %s to publish", r.repo, tag)
	}

	edit := &github.RepositoryRelease{Draft: github.Bool(false)}
	if latest {
		edit.MakeLatest = github.String("true")
	}
	if _, _, err := r.svc.EditRelease(ctx, r.repo.Org, r.repo.Name, rel.GetID(), edit); err != nil {
		return fmt.Errorf("publishing %s release %s: %w", r.repo, tag, err)
	}
	return nil
}

// LatestTag is the tag GitHub serves as the latest release
func (r *Releases) LatestTag(ctx context.Context) (string, error) {
	rel, resp, err := r.svc.GetLatestRelease(ctx, r.repo.Org, r.repo.Name)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return "", nil
		}
		return "", fmt.Errorf("%s latest release: %w", r.repo, err)
	}
	return rel.GetTagName(), nil
}

const pageSize = 100
