package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/sirupsen/logrus"
)

var create, publish bool

func init() {
	flag.BoolVar(&create, "create", false, "Create a release from the current commit")
	flag.BoolVar(&publish, "publish", false, "Publish the release built from the current tag")

	flag.Parse()
}

// Global configuration for releases.
var (
	registries = []string{"docker.io", "quay.io"}
)

func main() {
	if create {
		err := BuildRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to create Calico release")
		}
		return
	}

	if publish {
		err := PublishRelease()
		if err != nil {
			logrus.WithError(err).Error("Failed to publish Calico release")
		}
		return
	}

	logrus.Fatalf("No command specified")
}

// BuildRelease creates a Calico release.
func BuildRelease() error {
	// Check that the environment has the necessary prereqs.
	if err := releasePrereqs(); err != nil {
		return err
	}

	// Determine the release version to use, and tag the branch.
	ver := determineReleaseVersion()
	branch := determineBranch()
	logrus.WithFields(logrus.Fields{"branch": branch, "version": ver}).Infof("Creating Calico release from branch")
	_, err := git("tag", ver)
	if err != nil {
		return fmt.Errorf("Failed to tag release: %s", err)
	}

	// Successfully tagged. If we fail to release after this stage, we need to delete the tag.
	defer func() {
		if err != nil {
			logrus.Warn("Failed to release, cleaning up tag")
			git("tag", "-d", ver)
		}
	}()

	// Build container images for the release.
	if err = buildContainerImages(ver); err != nil {
		return err
	}

	// TODO: Assert the produced images are OK. e.g., have correct
	// commit and version information compiled in.

	// Build artifacts to upload to github.
	if err = collectGithubArtifacts(ver); err != nil {
		return err
	}

	return nil
}

func PublishRelease() error {
	// Determine the currently checked-out tag.
	ver, err := git("describe", "--exact-match", "--tags", "HEAD")
	if err != nil {
		return fmt.Errorf("failed to get tag for checked-out commit, is there one? %s", err)
	}

	// Check that the environment has the necessary prereqs.
	if err = publishPrereqs(ver); err != nil {
		return err
	}

	// Publish container images.
	if err = publishContainerImages(ver); err != nil {
		return err
	}

	return nil
}

// Check general prerequisites for cutting and publishing a release.
func releasePrereqs() error {
	// Check that we're not on the master branch. We never cut releases from master.
	branch := determineBranch()
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
func publishPrereqs(ver string) error {
	// TODO: Verify all required artifacts are present.
	return releasePrereqs()
}

// We include the following GitHub artifacts on each release. This function assumes
// that they have already been built, and simply wraps them up.
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// - tigera-operator-vX.Y.Z.tgz: contains the helm v3 chart.
// - calico-windows-vX.Y.Z.zip: Calico for Windows.
func collectGithubArtifacts(ver string) error {
	// Final artifacts will be moved here.
	uploadDir := fmt.Sprintf("_output/upload/%s", ver)
	// TODO: Delete if already exists.
	err := os.MkdirAll(uploadDir, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create dir: %s", err)
	}

	// Build and add in the complete release tarball.
	if err = buildReleaseTar(ver, uploadDir); err != nil {
		return err
	}

	// Add in the already-buily windows zip archive and helm chart.
	if _, err := runCommand("cp", []string{fmt.Sprintf("node/dist/calico-windows-%s.zip", ver), uploadDir}, nil); err != nil {
		return err
	}
	if _, err := runCommand("cp", []string{fmt.Sprintf("calico/bin/tigera-operator-%s.tgz", ver), uploadDir}, nil); err != nil {
		return err
	}

	return nil
}

// Builds the complete release tar for upload to github.
// - release-vX.Y.Z.tgz: contains images, manifests, and binaries.
// TODO: We should produce a tar per architecture that we ship.
func buildReleaseTar(ver string, targetDir string) error {
	// Create tar files for container image that are shipped.
	releaseBase := fmt.Sprintf("_output/release-%s", ver)
	err := os.MkdirAll(releaseBase+"/images", os.ModePerm)
	if err != nil {
		return fmt.Errorf("Failed to create images dir: %s", err)
	}
	outFmt := "_output/release-%s/images/%s"
	images := map[string]string{
		fmt.Sprintf("calico/node:%s", ver):                         fmt.Sprintf(outFmt, ver, "calico-node.tar"),
		fmt.Sprintf("calico/typha:%s", ver):                        fmt.Sprintf(outFmt, ver, "calico-typha.tar"),
		fmt.Sprintf("calico/cni:%s", ver):                          fmt.Sprintf(outFmt, ver, "calico-cni.tar"),
		fmt.Sprintf("calico/kube-controllers:%s", ver):             fmt.Sprintf(outFmt, ver, "calico-kube-controllers.tar"),
		fmt.Sprintf("calico/pod2daemon-flexvol:%s", ver):           fmt.Sprintf(outFmt, ver, "calico-pod2daemon.tar"),
		fmt.Sprintf("calico/dikastes:%s", ver):                     fmt.Sprintf(outFmt, ver, "calico-dikastes.tar"),
		fmt.Sprintf("calico/flannel-migration-controller:%s", ver): fmt.Sprintf(outFmt, ver, "calico-flannel-migration-controller.tar"),
	}
	for img, out := range images {
		err = archiveContainerImage(out, img)
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
		"cni-plugin/bin/github/": binDir + "/cni",

		// Calicoctl binaries.
		"calicoctl/bin/": binDir + "/calicoctl",

		// Felix binaries.
		"felix/bin/calico-bpf": binDir,
	}
	for src, dst := range binaries {
		if _, err := runCommand("cp", []string{"-r", src, dst}, nil); err != nil {
			return err
		}
	}

	// Add in manifests directory generated from the docs.
	if _, err := runCommand("cp", []string{"-r", "calico/_site/manifests", releaseBase}, nil); err != nil {
		return err
	}

	// tar up the whole thing.
	if _, err := runCommand("tar", []string{"-czvf", fmt.Sprintf("%s/release-%s.tgz", targetDir, ver), releaseBase}, nil); err != nil {
		return err
	}

	return nil
}

func buildContainerImages(ver string) error {
	releaseDirs := []string{
		"pod2daemon",
		"cni-plugin",
		"apiserver",
		"kube-controllers",
		"calicoctl",
		"app-policy",
		"typha",
		"felix",
		"node",
		"calico", // Technically not a container image, but a helm chart.
	}

	// Build env.
	// TODO: Pass CHART_RELEASE to calico repo if needed.
	env := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", ver),
	)

	for _, dir := range releaseDirs {
		err := makeInDirectory(dir, "release-build", env...)
		if err != nil {
			return fmt.Errorf("Failed to build %s: %s", dir, err)
		}
	}
	return nil
}

func publishContainerImages(ver string) error {
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
		"CONFIRM=false", // Undo this when done prototyping.
		"DRYRUN=true",   // Undo this when done prototyping.
	)

	for _, dir := range releaseDirs {
		out, err := makeInDirectoryWithOutput(dir, "release-publish", env...)
		if err != nil {
			return fmt.Errorf("Failed to publish %s: %s", dir, err)
		}
		logrus.Info(out)
	}
	return nil
}

// determineReleaseVersion uses historical clues to figure out the next semver
// release number to use for this release.
func determineReleaseVersion() string {
	// Check that we're not already on a git tag.
	_, err := git("describe", "--exact-match", "--tags", "HEAD")
	if err == nil {
		// On a current tag.
		out, _ := git("describe", "--tags", "--dirty", "--always", "--abbrev=12")
		logrus.Fatalf("Already on a tag (%s), refusing to create release", out)
	}

	// Determine the last tag on this branch.
	out, err := git("describe", "--tags", "--dirty", "--always", "--abbrev=12")
	if err != nil {
		logrus.WithError(err).Fatal("Failed to git describe")
	}
	logrus.WithField("out", out).Info("Current git describe")

	// There are two types of tag that this might be - either it was a previous patch release,
	// or it was a "vX.Y.Z-0.dev" tag produced when cutting the relaese branch.
	if strings.Contains(out, "-0.dev") {
		// This is the first release from this branch - we can simply extract the version from
		// the dev tag.
		return strings.Split(out, "-0.dev")[0]
	} else {
		// This is a patch release - we need to parse the previous, and
		// bump the patch version.
		previousVersion := strings.Split(out, "-")[0]
		logrus.WithField("previousVersion", previousVersion).Info("Previous version")
		v, err := semver.NewVersion(strings.TrimPrefix(previousVersion, "v"))
		if err != nil {
			logrus.WithField("previousVersion", previousVersion).WithError(err).Fatal("Failed to parse git version as semver")
		}
		v.BumpPatch()
		return fmt.Sprintf("v%s", v.String())
	}
}

// determineBranch returns the current checked out branch.
func determineBranch() string {
	out, err := git("rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		logrus.WithError(err).Fatal("Error determining branch")
	}
	return out
}

// Uses docker to build a tgz archive of the specified container image.
func archiveContainerImage(out, image string) error {
	_, err := runCommand("docker", []string{"save", "--output", out, image}, nil)
	return err
}

func git(args ...string) (string, error) {
	return runCommand("git", args, nil)
}

func makeInDirectory(dir, target string, env ...string) error {
	_, err := runCommand("make", []string{"-C", dir, target}, env)
	return err
}

func makeInDirectoryWithOutput(dir, target string, env ...string) (string, error) {
	return runCommand("make", []string{"-C", dir, target}, env)
}

func runCommand(name string, args []string, env []string) (string, error) {
	cmd := exec.Command(name, args...)
	if len(env) != 0 {
		cmd.Env = env
	}
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	logrus.WithField("cmd", cmd.String()).Infof("Running %s command", name)
	err := cmd.Run()
	fields := logrus.Fields{"stdout": outb.String(), "stderr": errb.String()}
	logrus.WithError(err).WithFields(fields).Debug("command output")
	if err != nil {
		err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(outb.String()), err
}
