// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
)

// recordingRunner runs nothing and records what it was asked to run. Units run
// concurrently, so recording is locked.
type recordingRunner struct {
	mu       sync.Mutex
	args     [][]string
	envs     [][]string
	logPaths []string
}

func (r *recordingRunner) record(args, env []string, logPath string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.args = append(r.args, slices.Clone(args))
	r.envs = append(r.envs, slices.Clone(env))
	r.logPaths = append(r.logPaths, logPath)
	return "", nil
}

func (r *recordingRunner) Run(_ string, args, env []string) (string, error) {
	return r.record(args, env, "")
}

func (r *recordingRunner) RunNoCapture(_ string, args, env []string) error {
	_, err := r.record(args, env, "")
	return err
}

func (r *recordingRunner) RunInDir(_, _ string, args, env []string) (string, error) {
	if slices.Contains(args, "build-images") {
		// The publish asks each directory for its image names before recording.
		if _, err := r.record(args, env, ""); err != nil {
			return "", err
		}
		return "calico calico-windows", nil
	}
	return r.record(args, env, "")
}

func (r *recordingRunner) RunInDirNoCapture(_, _ string, args, env []string) error {
	_, err := r.record(args, env, "")
	return err
}

func (r *recordingRunner) RunInDirToFile(_, _ string, args, env []string, logPath string) (string, error) {
	return r.record(args, env, logPath)
}

// envFor returns the environment of the first recorded make call whose args
// contain every one of want.
func (r *recordingRunner) envFor(want ...string) []string {
	for i, args := range r.args {
		if containsAll(args, want) {
			return r.envs[i]
		}
	}
	return nil
}

// ran reports whether any recorded call's args contain every one of want.
func (r *recordingRunner) ran(want ...string) bool {
	return slices.ContainsFunc(r.args, func(args []string) bool {
		return containsAll(args, want)
	})
}

func containsAll(args, want []string) bool {
	for _, w := range want {
		if !slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, w) }) {
			return false
		}
	}
	return true
}

// fakeRepo writes the two manifests VersionsFromManifests reads, so the image
// commands can resolve a version without a checkout.
func fakeRepo(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	manifests := filepath.Join(root, "manifests", "ocp")
	if err := os.MkdirAll(manifests, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(path, content string) {
		if err := os.WriteFile(filepath.Join(root, "manifests", path), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(filepath.Join("ocp", "02-tigera-operator.yaml"), "          image: quay.io/calico/calico:"+version+"\n")
	write("tigera-operator.yaml", "          image: quay.io/tigera/operator:"+version+"\n")
	return root
}

// runImages drives the real images command with a recording runner.
func runImages(t *testing.T, root string, args ...string) *recordingRunner {
	t.Helper()
	r := &recordingRunner{}
	prev, prevResolve := imagesRunner, imagesDigestResolver
	imagesRunner = r
	imagesDigestResolver = func(string) (string, bool, error) { return "sha256:aaa", true, nil }
	t.Cleanup(func() { imagesRunner, imagesDigestResolver = prev, prevResolve })

	cfg := &Config{
		RepoRootDir: root,
		TmpDir:      filepath.Join(root, "tmp"),
		OutputDir:   filepath.Join(root, "_output"),
		LogsDir:     filepath.Join(root, "_logs"),
	}
	cmd := imagesCommand(cfg)
	if err := cmd.Run(context.Background(), append([]string{"images"}, args...)); err != nil {
		t.Fatalf("images %s: %v", strings.Join(args, " "), err)
	}
	return r
}

// --local must reach make as DRYRUN, never CONFIRM.
func TestImagesPublishLocalIsDryRun(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--local", "--registry", "quay.io/calico", "--no-image-scan")

	if !r.ran("cmd/calico", "release-publish") {
		t.Fatalf("no release-publish for cmd/calico, ran: %v", r.args)
	}
	env := r.envFor("cmd/calico", "release-publish")
	if !slices.Contains(env, "DRYRUN=true") {
		t.Error("publish --local did not latch DRYRUN=true")
	}
	if slices.Contains(env, "CONFIRM=true") {
		t.Error("publish --local must not latch CONFIRM=true")
	}
	if !slices.Contains(env, "VERSION=v3.30.0") {
		t.Errorf("version not taken from the manifests, env: %v", env)
	}
}

// Without --local the publish latches CONFIRM, which is what actually pushes.
func TestImagesPublishLatchesConfirm(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--registry", "quay.io/calico", "--no-image-scan")

	env := r.envFor("cmd/calico", "release-publish")
	if !slices.Contains(env, "CONFIRM=true") {
		t.Error("publish did not latch CONFIRM=true")
	}
	if slices.Contains(env, "DRYRUN=true") {
		t.Error("publish must not latch DRYRUN=true")
	}
}

// felix is built but never published, and a build must not latch either
// publish flag.
func TestImagesBuildRunsFelixAndDoesNotPublish(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"), "build", "--registry", "quay.io/calico")

	if !r.ran("felix", "release-build") {
		t.Errorf("build did not run felix, ran: %v", r.args)
	}
	for _, env := range r.envs {
		for _, latch := range []string{"CONFIRM=true", "DRYRUN=true", "RELEASE=true"} {
			if slices.Contains(env, latch) {
				t.Errorf("build must not set %s", latch)
			}
		}
	}
}

// Each unit logs to its own file under the image step's directory.
func TestImagesLogPaths(t *testing.T) {
	root := fakeRepo(t, "v3.30.0")
	r := runImages(t, root, "build", "--registry", "quay.io/calico")

	want := map[string]string{
		"node.log":         filepath.Join(root, "_logs", "images-build", "node.log"),
		"node-windows.log": filepath.Join(root, "_logs", "images-build", "node-windows.log"),
	}
	for name, path := range want {
		if !slices.Contains(r.logPaths, path) {
			t.Errorf("no unit logged to %s (%s), got %v", name, path, r.logPaths)
		}
	}
}

var _ command.CommandRunner = (*recordingRunner)(nil)

// Narrowing must scope the work to the named directories.
func TestImagesNarrowedToReleaseDirs(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--local", "--registry", "quay.io/calico", "--no-image-scan",
		"--image-release-dir", "whisker")

	if len(r.args) != 1 {
		t.Fatalf("expected one unit for whisker, ran: %v", r.args)
	}
	if !r.ran("whisker", "release-publish") {
		t.Errorf("did not publish whisker, ran: %v", r.args)
	}
}

// A directory shipping two image kinds keeps both when narrowed to it.
func TestImagesNarrowedKeepsEveryVariant(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--local", "--registry", "quay.io/calico", "--no-image-scan",
		"--image-release-dir", "node")

	if !r.ran("node", "release-publish") {
		t.Errorf("did not publish the standard node image, ran: %v", r.args)
	}
	if !r.ran("node", "release-windows") {
		t.Errorf("did not publish the windows node image, ran: %v", r.args)
	}
}

// felix is build-only: accepted for a build, absent from a publish.
func TestImagesNarrowedToBuildOnlyDir(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"build", "--registry", "quay.io/calico", "--image-release-dir", "felix")

	if len(r.args) != 1 || !r.ran("felix", "release-build") {
		t.Fatalf("expected a single felix build, ran: %v", r.args)
	}
}

// An unknown directory must be rejected: narrowing silently drops what it does
// not recognise.
func TestImagesRejectsUnknownReleaseDir(t *testing.T) {
	prev := imagesRunner
	imagesRunner = &recordingRunner{}
	t.Cleanup(func() { imagesRunner = prev })

	root := fakeRepo(t, "v3.30.0")
	cfg := &Config{
		RepoRootDir: root,
		TmpDir:      filepath.Join(root, "tmp"),
		OutputDir:   filepath.Join(root, "_output"),
		LogsDir:     filepath.Join(root, "_logs"),
	}
	err := imagesCommand(cfg).Run(context.Background(), []string{
		"images", "publish", "--local", "--registry", "quay.io/calico",
		"--no-image-scan", "--image-release-dir", "nonesuch",
	})
	if err == nil {
		t.Fatal("expected an error for an unknown release dir")
	}
	if !strings.Contains(err.Error(), "nonesuch") {
		t.Errorf("error should name the invalid dir, got %q", err)
	}
}

// --from-registry retags what is already published, so make sees the source
// registry and tag.
func TestImagesPublishRetagsFromRegistry(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--registry", "quay.io/calico", "--no-image-scan",
		"--image-release-dir", "whisker",
		"--from-registry", "gcr.io/dev", "--from-tag", "v3.30.0-0.dev-abc")

	env := r.envFor("whisker", "release-publish")
	for _, want := range []string{
		"IMAGE_ONLY=true",
		"DEV_TAG=v3.30.0-0.dev-abc",
		"DEV_REGISTRIES=gcr.io/dev",
		"RELEASE_REGISTRIES=quay.io/calico",
		"RELEASE_TAG=v3.30.0",
	} {
		if !slices.Contains(env, want) {
			t.Errorf("retag env missing %s, got %v", want, env)
		}
	}
	if slices.Contains(env, "SKIP_DEV_IMAGE_RETAG=true") {
		t.Error("dev image retag was skipped without being asked")
	}
}

func TestImagesPublishSkipDevImageRetag(t *testing.T) {
	r := runImages(t, fakeRepo(t, "v3.30.0"),
		"publish", "--registry", "quay.io/calico", "--no-image-scan",
		"--image-release-dir", "whisker",
		"--from-registry", "gcr.io/dev", "--from-tag", "v3.30.0-0.dev-abc",
		"--skip-dev-image-retag")

	if env := r.envFor("whisker", "release-publish"); !slices.Contains(env, "SKIP_DEV_IMAGE_RETAG=true") {
		t.Errorf("--skip-dev-image-retag did not reach make, got %v", env)
	}
}

// The two retag flags are meaningless apart, so one without the other is an
// error rather than a silent fresh push.
func TestImagesPublishRejectsHalfConfiguredRetag(t *testing.T) {
	prev := imagesRunner
	imagesRunner = &recordingRunner{}
	t.Cleanup(func() { imagesRunner = prev })

	root := fakeRepo(t, "v3.30.0")
	cfg := &Config{
		RepoRootDir: root,
		TmpDir:      filepath.Join(root, "tmp"),
		OutputDir:   filepath.Join(root, "_output"),
		LogsDir:     filepath.Join(root, "_logs"),
	}
	err := imagesCommand(cfg).Run(context.Background(), []string{
		"images", "publish", "--registry", "quay.io/calico", "--no-image-scan",
		"--from-registry", "gcr.io/dev",
	})
	if err == nil {
		t.Fatal("expected an error when --from-tag is missing")
	}
	if !strings.Contains(err.Error(), "fromTag") {
		t.Errorf("error should name the missing setting, got %q", err)
	}
}

// An un-narrowed scan must cover every directory that produces an image,
// including those shipping only a Windows one.
func TestImagesPublishScansEveryImageDir(t *testing.T) {
	dirs := utils.ImageDiscoveryDirs()
	for _, want := range utils.WindowsReleaseDirs {
		if !slices.Contains(dirs, want) {
			t.Errorf("scan dirs omit %s, so its images would go unscanned", want)
		}
	}
	for _, want := range utils.ImageReleaseDirs {
		if !slices.Contains(dirs, want) {
			t.Errorf("scan dirs omit %s", want)
		}
	}
}
