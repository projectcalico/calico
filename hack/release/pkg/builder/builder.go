// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package builder

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/sirupsen/logrus"
)

// Global configuration for releases.
var (
	// Registries to which all release images are pushed.
	registries = []string{
		"docker.io/calico",
		"quay.io/calico",
		"gcr.io/projectcalico-org",
		"eu.gcr.io/projectcalico-org",
		"asia.gcr.io/projectcalico-org",
		"us.gcr.io/projectcalico-org",
	}

	// Git configuration for publishing to GitHub.
	organization = "projectcalico"
	repo         = "calico"
	origin       = "origin"
)

func NewReleaseBuilder(runner CommandRunner) *ReleaseBuilder {
	return &ReleaseBuilder{
		runner: runner,
	}
}

type ReleaseBuilder struct {
	// Allow specification of command runner so it can be overridden in tests.
	runner CommandRunner
}

// BuildRelease creates a Calico release.
func (r *ReleaseBuilder) BuildRelease() error {
	// Check that we're not already on a git tag.
	_, err := r.git("describe", "--exact-match", "--tags", "HEAD")
	if err == nil {
		// On a current tag.
		out, _ := r.git("describe", "--tags", "--dirty", "--always", "--abbrev=12")
		return fmt.Errorf("Already on a tag (%s), refusing to create release", out)
	}

	// Check that the repository is not a shallow clone. We need correct history.
	out, err := r.git("rev-parse", "--is-shallow-repository")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) == "true" {
		return fmt.Errorf("Attempt to release from a shallow clone is not possible")
	}

	// Check that the environment has the necessary prereqs.
	if err := r.releasePrereqs(); err != nil {
		return err
	}

	// Determine the last tag on this branch.
	out, err = r.git("describe", "--tags", "--dirty", "--always", "--abbrev=12")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to git describe")
	}
	logrus.WithField("out", out).Info("Current git describe")

	// Determine the release version to use based on the last tag, and then tag the branch.
	ver, err := r.determineReleaseVersion(out)
	if err != nil {
		return err
	}
	branch := r.determineBranch()
	logrus.WithFields(logrus.Fields{"branch": branch, "version": ver}).Infof("Creating Calico release from branch")
	_, err = r.git("tag", ver)
	if err != nil {
		return fmt.Errorf("Failed to tag release: %s", err)
	}

	// Successfully tagged. If we fail to release after this stage, we need to delete the tag.
	defer func() {
		if err != nil {
			logrus.Warn("Failed to release, cleaning up tag")
			r.git("tag", "-d", ver)
		}
	}()

	// Build container images for the release.
	if err = r.buildContainerImages(ver); err != nil {
		return err
	}

	// TODO: Assert the produced images are OK. e.g., have correct
	// commit and version information compiled in.

	// Build artifacts to upload to github.
	if err = r.collectGithubArtifacts(ver); err != nil {
		return err
	}

	return nil
}

func (r *ReleaseBuilder) PublishRelease() error {
	// Determine the currently checked-out tag.
	ver, err := r.git("describe", "--exact-match", "--tags", "HEAD")
	if err != nil {
		return fmt.Errorf("failed to get tag for checked-out commit, is there one? %s", err)
	}

	// Check that the environment has the necessary prereqs.
	if err = r.publishPrereqs(ver); err != nil {
		return err
	}

	// Publish container images.
	if err = r.publishContainerImages(ver); err != nil {
		return fmt.Errorf("failed to publish container images: %s", err)
	}

	// If all else is successful, push the git tag.
	if _, err = r.git("push", origin, ver); err != nil {
		return fmt.Errorf("failed to push git tag: %s", err)
	}

	// Publish the release to github.
	if err = r.publishGithubRelease(ver); err != nil {
		return fmt.Errorf("failed to publish github release: %s", err)
	}

	return nil
}

func (r *ReleaseBuilder) NewBranch() error {
	// Check that we're on the master branch. We always cut branches from master.
	branch := r.determineBranch()
	if branch != "master" {
		return fmt.Errorf("Release branches can only be cut from master")
	}

	// Determine the version for the branch. We can get this from the previous dev tag.
	out, err := r.git("describe", "--tags", "--dirty", "--always", "--abbrev=12")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to git describe")
	}
	logrus.WithField("out", out).Info("Current git describe")
	if !strings.Contains(out, "-0.dev") {
		return fmt.Errorf("Unable to determine release branch name from tag: %s", out)
	}

	// Determine the name of the new branch.
	nextBranchVersion := strings.Split(out, "-0.dev")[0]
	sv, err := semver.NewVersion(strings.TrimPrefix(nextBranchVersion, "v"))
	branchName := fmt.Sprintf("release-v%d.%d", sv.Major, sv.Minor)
	logrus.WithField("branch", branchName).Info("Next release branch")

	// Determine the next -0.dev tag.
	nextVersion := fmt.Sprintf("v%d.%d.0", sv.Major, sv.Minor+1)
	newDevTag := fmt.Sprintf("%s-0.dev", nextVersion)
	logrus.WithField("tag", newDevTag).Info("Next dev tag")

	// Create a new branch from the current master.
	r.gitOrFail("checkout", "-b", branchName)
	r.gitOrFail("push", origin, branchName)

	// Create the new dev tag on master and push it.
	r.gitOrFail("checkout", "master")
	r.gitOrFail("commit", "--allow-empty", "-m", fmt.Sprintf("Begin development on %s", nextVersion))
	r.gitOrFail("tag", newDevTag)
	r.gitOrFail("push", origin, "master")
	r.gitOrFail("push", origin, newDevTag)

	return nil
}

// Check general prerequisites for cutting and publishing a release.
func (r *ReleaseBuilder) releasePrereqs() error {
	// Check that we're not on the master branch. We never cut releases from master.
	branch := r.determineBranch()
	if branch == "master" {
		return fmt.Errorf("Cannot cut release from branch: %s", branch)
	}

	// Make sure we have a github token - needed for publishing to GH.
	// Strictly only needed for publishing, but we check during release anyway so
	// that we don't get all the way through the build to find out we're missing it!
	if token := os.Getenv("GITHUB_TOKEN"); token == "" {
		return fmt.Errorf("No GITHUB_TOKEN present in environment")
	}

	// TODO: Make sure the environment isn't dirty.
	return nil
}

// Prerequisites specific to publishing a release.
func (r *ReleaseBuilder) publishPrereqs(ver string) error {
	// TODO: Verify all required artifacts are present.
	return r.releasePrereqs()
}

// We include the following GitHub artifacts on each release. This function assumes
// that they have already been built, and simply wraps them up.
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// - tigera-operator-vX.Y.Z.tgz: contains the helm v3 chart.
// - calico-windows-vX.Y.Z.zip: Calico for Windows.
func (r *ReleaseBuilder) collectGithubArtifacts(ver string) error {
	// Final artifacts will be moved here.
	uploadDir := r.uploadDir(ver)
	// TODO: Delete if already exists.
	err := os.MkdirAll(uploadDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create dir: %s", err)
	}

	// We attach calicoctl binaries directly to the release as well.
	files, err := ioutil.ReadDir("calicoctl/bin/")
	if err != nil {
		return err
	}
	for _, b := range files {
		if _, err := r.runner.Run("cp", []string{fmt.Sprintf("calicoctl/bin/%s", b.Name()), uploadDir}, nil); err != nil {
			return err
		}
	}

	// Build and add in the complete release tarball.
	if err = r.buildReleaseTar(ver, uploadDir); err != nil {
		return err
	}

	// Add in the already-built windows zip archive, the Windows install script, and the helm chart.
	if _, err := r.runner.Run("cp", []string{fmt.Sprintf("node/dist/calico-windows-%s.zip", ver), uploadDir}, nil); err != nil {
		return err
	}
	if _, err := r.runner.Run("cp", []string{"calico/_site/scripts/install-calico-windows.ps1", uploadDir}, nil); err != nil {
		return err
	}
	if _, err := r.runner.Run("cp", []string{fmt.Sprintf("calico/bin/tigera-operator-%s.tgz", ver), uploadDir}, nil); err != nil {
		return err
	}

	return nil
}

func (r *ReleaseBuilder) uploadDir(ver string) string {
	return fmt.Sprintf("_output/upload/%s", ver)
}

// Builds the complete release tar for upload to github.
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// TODO: We should produce a tar per architecture that we ship.
func (r *ReleaseBuilder) buildReleaseTar(ver string, targetDir string) error {
	// Create tar files for container image that are shipped.
	releaseBase := fmt.Sprintf("_output/release-%s", ver)
	err := os.MkdirAll(releaseBase+"/images", os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create images dir: %s", err)
	}
	outFmt := "_output/release-%s/images/%s"
	registry := registries[0]
	images := map[string]string{
		fmt.Sprintf("%s/node:%s", registry, ver):                         fmt.Sprintf(outFmt, ver, "calico-node.tar"),
		fmt.Sprintf("%s/typha:%s", registry, ver):                        fmt.Sprintf(outFmt, ver, "calico-typha.tar"),
		fmt.Sprintf("%s/cni:%s", registry, ver):                          fmt.Sprintf(outFmt, ver, "calico-cni.tar"),
		fmt.Sprintf("%s/kube-controllers:%s", registry, ver):             fmt.Sprintf(outFmt, ver, "calico-kube-controllers.tar"),
		fmt.Sprintf("%s/pod2daemon-flexvol:%s", registry, ver):           fmt.Sprintf(outFmt, ver, "calico-pod2daemon.tar"),
		fmt.Sprintf("%s/dikastes:%s", registry, ver):                     fmt.Sprintf(outFmt, ver, "calico-dikastes.tar"),
		fmt.Sprintf("%s/flannel-migration-controller:%s", registry, ver): fmt.Sprintf(outFmt, ver, "calico-flannel-migration-controller.tar"),
	}
	for img, out := range images {
		err = r.archiveContainerImage(out, img)
		if err != nil {
			return err
		}

	}

	// Add in release binaries that we ship.
	binDir := fmt.Sprintf("%s/bin", releaseBase)
	err = os.MkdirAll(binDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create images dir: %s", err)
	}

	binaries := map[string]string{
		// CNI plugin binaries are all placed in github dir.
		"cni-plugin/bin/": binDir + "/cni",

		// Calicoctl binaries.
		"calicoctl/bin/": binDir + "/calicoctl",

		// Felix binaries.
		"felix/bin/calico-bpf": binDir,
	}
	for src, dst := range binaries {
		if _, err := r.runner.Run("cp", []string{"-r", src, dst}, nil); err != nil {
			return err
		}
	}

	// Add in manifests directory generated from the docs.
	if _, err := r.runner.Run("cp", []string{"-r", "calico/_site/manifests", releaseBase}, nil); err != nil {
		return err
	}

	// tar up the whole thing.
	if _, err := r.runner.Run("tar", []string{"-czvf", fmt.Sprintf("_output/release-%s.tgz", ver), "-C", "_output", fmt.Sprintf("release-%s", ver)}, nil); err != nil {
		return err
	}
	if _, err := r.runner.Run("cp", []string{fmt.Sprintf("_output/release-%s.tgz", ver), targetDir}, nil); err != nil {
		return err
	}

	return nil
}

func (r *ReleaseBuilder) buildContainerImages(ver string) error {
	releaseDirs := []string{
		"node",
		"pod2daemon",
		"cni-plugin",
		"apiserver",
		"kube-controllers",
		"calicoctl",
		"app-policy",
		"typha",
		"felix",
		"calico", // Technically not a container image, but a helm chart.
	}

	// Build env.
	// TODO: Pass CHART_RELEASE to calico repo if needed.
	env := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", ver),
		fmt.Sprintf("DEV_REGISTRIES=%s", strings.Join(registries, " ")),
	)

	for _, dir := range releaseDirs {
		out, err := r.makeInDirectoryWithOutput(dir, "release-build", env...)
		if err != nil {
			logrus.Error(out)
			return fmt.Errorf("Failed to build %s: %s", dir, err)
		}
		logrus.Info(out)
	}
	return nil
}

func (r *ReleaseBuilder) publishGithubRelease(ver string) error {
	releaseNoteTemplate := `
Release notes can be found at https://projectcalico.docs.tigera.io/archive/{release_stream}/release-notes/

Attached to this release are the following artifacts:

- {release_tar}: container images, binaries, and kubernetes manifests.
- {calico_windows_zip}: Calico for Windows.
- {helm_chart}: Calico Helm v3 chart.
`
	sv, err := semver.NewVersion(strings.TrimPrefix(ver, "v"))
	if err != nil {
		return err
	}
	formatters := []string{
		// Alternating placeholder / filler. We can't use backticks in the multiline string above,
		// so we replace anything that needs to be backticked into it here.
		"{version}", ver,
		"{release_stream}", fmt.Sprintf("v%d.%d", sv.Major, sv.Minor),
		"{release_tar}", fmt.Sprintf("`release-%s.tgz`", ver),
		"{calico_windows_zip}", fmt.Sprintf("`calico-windows-%s.zip`", ver),
		"{helm_chart}", fmt.Sprintf("`tigera-operator-%s.tgz`", ver),
	}
	replacer := strings.NewReplacer(formatters...)
	releaseNote := replacer.Replace(releaseNoteTemplate)

	args := []string{
		"-username", organization,
		"-repository", repo,
		"-name", ver,
		"-body", releaseNote,
		ver,
		r.uploadDir(ver),
	}
	_, err = r.runner.Run("./hack/release/ghr", args, nil)
	return err
}

func (r *ReleaseBuilder) publishContainerImages(ver string) error {
	releaseDirs := []string{
		"pod2daemon",
		"cni-plugin",
		"apiserver",
		"kube-controllers",
		"calicoctl",
		"app-policy",
		"typha",
		"node",
	}

	env := append(os.Environ(),
		fmt.Sprintf("IMAGETAG=%s", ver),
		fmt.Sprintf("VERSION=%s", ver),
		"RELEASE=true",
		"CONFIRM=true",
		fmt.Sprintf("DEV_REGISTRIES=%s", strings.Join(registries, " ")),
	)

	// We allow for a certain number of retries when publishing each directory, since
	// network flakes can occasionally result in images failing to push.
	maxRetries := 1
	for _, dir := range releaseDirs {
		attempt := 0
		for {
			out, err := r.makeInDirectoryWithOutput(dir, "release-publish", env...)
			if err != nil {
				if attempt < maxRetries {
					logrus.WithField("attempt", attempt).WithError(err).Warn("Publish failed, retrying")
					attempt++
					continue
				}
				logrus.Error(out)
				return fmt.Errorf("Failed to publish %s: %s", dir, err)
			}

			// Success - move on to the next directory.
			logrus.Info(out)
			break
		}
	}
	return nil
}

// determineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release.
func (r *ReleaseBuilder) determineReleaseVersion(previousTag string) (string, error) {
	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-0.dev" tag produced when cutting the relaese branch.
	if strings.Contains(previousTag, "-0.dev") {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		return strings.Split(previousTag, "-0.dev")[0], nil
	} else {
		// This is a patch release - we need to parse the previous, and
		// bump the patch version.
		previousVersion := strings.Split(previousTag, "-")[0]
		logrus.WithField("previousVersion", previousVersion).Info("Previous version")
		v, err := semver.NewVersion(strings.TrimPrefix(previousVersion, "v"))
		if err != nil {
			logrus.WithField("previousVersion", previousVersion).WithError(err).Error("Failed to parse git version as semver")
			return "", fmt.Errorf("failed to parse git version as semver: %s", err)
		}
		v.BumpPatch()
		return fmt.Sprintf("v%s", v.String()), nil
	}
}

// determineBranch returns the current checked out branch.
func (r *ReleaseBuilder) determineBranch() string {
	out, err := r.git("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		logrus.WithError(err).Fatal("Error determining branch")
	} else if strings.TrimSpace(out) == "HEAD" {
		logrus.Fatal("Not on a branch, refusing to cut release")
	}
	return strings.TrimSpace(out)
}

// Uses docker to build a tgz archive of the specified container image.
func (r *ReleaseBuilder) archiveContainerImage(out, image string) error {
	_, err := r.runner.Run("docker", []string{"save", "--output", out, image}, nil)
	return err
}

func (r *ReleaseBuilder) git(args ...string) (string, error) {
	return r.runner.Run("git", args, nil)
}

func (r *ReleaseBuilder) gitOrFail(args ...string) {
	_, err := r.runner.Run("git", args, nil)
	if err != nil {
		logrus.WithError(err).Fatal("git command failed")
	}
}

func (r *ReleaseBuilder) makeInDirectory(dir, target string, env ...string) error {
	_, err := r.runner.Run("make", []string{"-C", dir, target}, env)
	return err
}

func (r *ReleaseBuilder) makeInDirectoryWithOutput(dir, target string, env ...string) (string, error) {
	return r.runner.Run("make", []string{"-C", dir, target}, env)
}
