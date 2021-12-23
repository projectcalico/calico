package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-semver/semver"
	"github.com/sirupsen/logrus"
)

func main() {
	err := DoRelease()
	if err != nil {
		logrus.WithError(err).Error("Failed to produce Calico release")
	}
}

// DoRelease creates a Calico release.
func DoRelease() error {
	// Check that we're not on the master branch. We never cut releases from master.
	branch := determineBranch()
	if branch == "master" {
		return fmt.Errorf("Cannot cut release from branch: %s", branch)
	}

	// Check that the environment has the necessary prereqs.
	if err := checkEnvironment(); err != nil {
		return err
	}

	// Determine the release version to use, and tag the branch.
	ver := determineReleaseVersion()
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

	return nil
}

func checkEnvironment() error {
	// Make sure we have a github token - needed for publishing to GH.
	if token := os.Getenv("GITHUB_TOKEN"); token == "" {
		return fmt.Errorf("No GITHUB_TOKEN present in environment")
	}

	// TODO: Make sure the environment isn't dirty.
	return nil
}

func buildContainerImages(ver string) error {
	// Map of release directory, to build command (if needed).
	releaseDirs := []string{
		"pod2daemon",
		"cni-plugin",
		"apiserver",
		"kube-controllers",
		"calicoctl",
		"app-policy",
		"typha",
		"node",
		"calico",
	}

	// Build env.
	env := append(os.Environ(),
		fmt.Sprintf("VERSION=%s", ver),
	)

	// TODO: Pass CHART_RELEASE to calico repo if needed.
	for _, dir := range releaseDirs {
		err := makeInDirectory(dir, "release-build", env...)
		if err != nil {
			return fmt.Errorf("Failed to build %s: %s", dir, err)
		}
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

// git runs a git command in the repository.
func git(args ...string) (string, error) {
	logrus.WithField("cmd", args).Debug("Running git command")
	cmd := exec.Command("git", args...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	fields := logrus.Fields{"stdout": outb.String(), "stderr": errb.String()}
	logrus.WithError(err).WithFields(fields).Debug("git output")
	if err != nil {
		err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(outb.String()), err
}

func makeInDirectory(dir, target string, env ...string) error {
	cmd := exec.Command("make", "-C", dir, target)
	cmd.Env = env
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	logrus.WithField("cmd", cmd.String()).Info("Running make command")
	err := cmd.Run()
	fields := logrus.Fields{"stdout": outb.String(), "stderr": errb.String()}
	logrus.WithError(err).WithFields(fields).Debug("make output")
	if err != nil {
		err = fmt.Errorf("%s: %s", err, strings.TrimSpace(errb.String()))
		return err
	}
	return nil
}
