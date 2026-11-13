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
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Masterminds/semver/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/distribution"
	"github.com/projectcalico/calico/release/internal/outputs"
	"github.com/projectcalico/calico/release/internal/steps"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

const ReleaseStep = "github-release"

// Each section ends in a blank line, so leaving one out leaves no gap.
const releaseNoteTemplate = `
Release notes can be found [{{.Link.Text}}]({{.Link.URL}})

{{if .Artifacts -}}Attached to this release are the following artifacts:

{{range .Artifacts}}- ` + "`{{.Name}}`" + `: {{.Description}}
{{end}}
{{end}}{{if .AdditionalLinks}}Additional links:

{{range .AdditionalLinks}}- [{{.Text}}]({{.URL}})
{{end}}
{{end}}`

var draftRelease = true

var (
	_ distribution.Handler        = Release{}
	_ distribution.ArtifactLister = Release{}
	_ distribution.Validator      = Release{}
)

// ReleaseOptions describes a GitHub release. An empty Source makes a release
// with only a body.
type ReleaseOptions struct {
	Repo    Repo
	Version version.Version
	Source  string
	Notes   ReleaseNotes

	Skip   bool
	Draft  bool
	DryRun bool

	Runner command.CommandRunner
}

// ReleaseNotes is what a release's body says. Link.Text finishes "Release
// notes can be found", so it carries its own preposition, such as "on GitHub".
type ReleaseNotes struct {
	Link            Link
	Artifacts       []ReleaseArtifact
	AdditionalLinks []Link
}

type ReleaseArtifact struct {
	Name        string
	Description string
}

type Link struct {
	Text string
	URL  string
}

func ReleaseUpload(o ReleaseOptions) distribution.Upload {
	ver := o.Version.String()
	requires := []string{TagStep}
	if o.Source != "" {
		requires = []string{outputs.MetadataStep, distribution.ChecksumStep, TagStep}
	}
	return distribution.Upload{
		Name:     ReleaseStep,
		Source:   o.Source,
		Skip:     o.Skip,
		Requires: requires,
		Handler: Release{
			Repo:   o.Repo,
			Tag:    ver,
			Notes:  o.Notes,
			Draft:  o.Draft,
			DryRun: o.DryRun,
			Runner: o.Runner,
		},
	}
}

type Release struct {
	Repo  Repo
	Tag   string
	Title string

	Notes ReleaseNotes

	Draft  bool
	DryRun bool

	Log    *logrus.Entry
	Runner command.CommandRunner

	releases *Releases
}

func (d Release) Name() string { return fmt.Sprintf("%s github release", d.Tag) }

func (d Release) Validate(distribution.Upload) error {
	var errs []error
	if err := d.Repo.Validate(); err != nil {
		errs = append(errs, err)
	}
	if d.Notes.Link.Text == "" || d.Notes.Link.URL == "" {
		errs = append(errs, fmt.Errorf("release notes need link text and a URL"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", d.Name(), err)
	}
	return nil
}

func (d Release) body() (string, error) {
	tmpl, err := template.New("release-note").Option("missingkey=error").Parse(releaseNoteTemplate)
	if err != nil {
		return "", fmt.Errorf("parse release note: %w", err)
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, d.Notes); err != nil {
		return "", fmt.Errorf("render release note: %w", err)
	}
	return b.String(), nil
}

func (d Release) client() (*Releases, error) {
	if d.releases != nil {
		return d.releases, nil
	}
	return NewReleases(d.Repo, Client(d.Runner).Repositories)
}

func (d Release) Publish(ctx context.Context, src string) error {
	tag, err := d.semver(d.Tag)
	if err != nil {
		return fmt.Errorf("parse release tag %q: %w", d.Tag, err)
	}
	prerelease := tag.Prerelease() != ""
	body, err := d.body()
	if err != nil {
		return err
	}
	var files []string
	if src != "" {
		if files, err = utils.TopLevelFiles(src, distribution.SumsFileName); err != nil {
			return fmt.Errorf("get files: %w", err)
		}
		if len(files) == 0 {
			return fmt.Errorf("no release files %s", d.Tag)
		}
	}
	if d.DryRun {
		d.log().WithFields(logrus.Fields{"files": files, "prerelease": prerelease}).Infof("Dry run, not creating %s", d.Name())
		return nil
	}
	if src != "" {
		// Written by an earlier step, and excluded from the listing so a re-run
		// does not checksum it into itself.
		sums := filepath.Join(src, distribution.SumsFileName)
		if _, err := os.Stat(sums); err != nil {
			return fmt.Errorf("%s: %w", distribution.SumsFileName, err)
		}
		files = append(files, sums)
	}
	gh, err := d.client()
	if err != nil {
		return fmt.Errorf("github client: %w", err)
	}
	rel, err := gh.Create(ctx, CreateOptions{
		Tag:        d.Tag,
		Name:       d.releaseName(),
		Body:       body,
		Draft:      draftRelease,
		Prerelease: prerelease,
	})
	if err != nil {
		return fmt.Errorf("create release: %w", err)
	}

	if len(files) > 0 {
		assets, err := steps.Go(files, NewAsset)
		if err != nil {
			return fmt.Errorf("release assets: %w", err)
		}
		missing, err := gh.SyncAssets(ctx, rel.GetID(), assets)
		if err != nil {
			return fmt.Errorf("check existing assets: %w", err)
		}
		d.log().WithFields(logrus.Fields{"upload": len(missing), "attached": len(files) - len(missing)}).Info("Release assets")

		_, err = steps.GoLimit(missing, steps.MaxConcurrency, func(a Asset) (struct{}, error) {
			return struct{}{}, d.upload(ctx, gh, rel.GetID(), a)
		})
		if err != nil {
			return fmt.Errorf("upload assets: %w", err)
		}
	}
	if d.Draft {
		return nil
	}
	// Semver ranks a pre-release above older final releases.
	latest := false
	if !prerelease {
		if latest, err = d.makeLatest(ctx); err != nil {
			return fmt.Errorf("make latest: %w", err)
		}
	}
	return gh.Publish(ctx, d.Tag, latest)
}

func (d Release) Artifacts(src string) ([]outputs.ArtifactFile, error) {
	if src == "" {
		return nil, nil
	}
	return outputs.ArtifactsAt(src, d.Repo.DownloadURL(d.Tag), distribution.SumsFileName)
}

func (d Release) makeLatest(ctx context.Context) (bool, error) {
	gh, err := d.client()
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

func (d Release) semver(tag string) (*semver.Version, error) {
	return semver.NewVersion(strings.TrimPrefix(tag, "v"))
}

func (d Release) upload(ctx context.Context, gh *Releases, releaseID int64, a Asset) error {
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

func (d Release) releaseName() string {
	if d.Title == "" {
		return d.Tag
	}
	return d.Title
}

func (d Release) log() *logrus.Entry {
	if d.Log == nil {
		return logrus.NewEntry(logrus.StandardLogger())
	}
	return d.Log
}
