// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package branch

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/release/internal/command"
	"github.com/projectcalico/calico/release/internal/utils"
	"github.com/projectcalico/calico/release/internal/version"
)

type BranchManager struct {
	// repoRoot is the absolute path to the root directory of the repository
	repoRoot string

	// origin remote repository
	remote string

	// mainBranch is the main/default branch of the repository
	mainBranch string

	// devTag is the development tag identifier
	devTagIdentifier string

	// releaseBranchPrefix is the prefix for the release branch
	releaseBranchPrefix string

	// validate indicates if we should run pre-branch validation
	validate bool

	// publish indicates if we should push the branch changes to the remote repository
	publish bool
}

func NewManager(opts ...Option) *BranchManager {
	b := &BranchManager{
		validate: true,
		publish:  false,
	}

	// Apply the options
	for _, o := range opts {
		if err := o(b); err != nil {
			logrus.WithError(err).Fatal("Failed to apply option")
		}
	}

	// Validate the configuration
	if b.repoRoot == "" {
		logrus.Fatal("No repository root specified")
	}
	if b.remote == "" {
		logrus.Fatal("No remote repository source specified")
	}
	if b.mainBranch == "" {
		logrus.Fatal("No main branch specified")
	}
	if b.devTagIdentifier == "" {
		logrus.Fatal("No development tag identifier specified")
	}
	if b.releaseBranchPrefix == "" {
		logrus.Fatal("No release branch prefix specified")
	}

	logrus.WithFields(logrus.Fields{
		"repoRoot":            b.repoRoot,
		"remote":              b.remote,
		"mainBranch":          b.mainBranch,
		"releaseBranchPrefix": b.releaseBranchPrefix,
		"devTagIdentifier":    b.devTagIdentifier,
	}).Debug("Using configuration")

	return b
}

func (b *BranchManager) CutVersionedBranch(version string) error {
	if b.validate {
		if err := b.PreBranchCutValidation(); err != nil {
			return fmt.Errorf("pre-branch cut validation failed: %s", err)
		}
	}
	newBranchName := fmt.Sprintf("%s-%s", b.releaseBranchPrefix, version)
	logrus.WithField("branch", newBranchName).Info("Creating new release branch")
	if _, err := b.git("checkout", "-b", newBranchName); err != nil {
		return err
	}
	if b.publish {
		if _, err := b.git("push", b.remote, newBranchName); err != nil {
			return err
		}
	}
	return nil
}

func (b *BranchManager) CutReleaseBranch() error {
	if b.validate {
		if err := b.PreBranchCutValidation(); err != nil {
			return fmt.Errorf("pre-branch cut validation failed: %s", err)
		}
	}
	gitVersion, err := command.GitVersion(b.repoRoot, true)
	if err != nil {
		return err
	}
	ver := version.New(gitVersion)
	currentVersion := ver.Semver()
	if err := b.CutVersionedBranch(fmt.Sprintf("v%d.%d", currentVersion.Major(), currentVersion.Minor())); err != nil {
		return err
	}
	if _, err := b.git("checkout", b.mainBranch); err != nil {
		return err
	}
	nextVersion := currentVersion.IncMinor()
	nextVersionTag := fmt.Sprintf("v%d.%d.%d-%s", nextVersion.Major(), nextVersion.Minor(), nextVersion.Patch(), b.devTagIdentifier)
	logrus.WithField("tag", nextVersionTag).Info("Creating new development tag")
	if _, err := b.git("commit", "--allow-empty", "-m", fmt.Sprintf("Begin development on  v%d.%d", nextVersion.Major(), nextVersion.Minor())); err != nil {
		return err
	}
	if b.publish {
		if _, err := b.git("push", b.remote, b.mainBranch); err != nil {
			return err
		}
		if _, err := b.git("tag", nextVersionTag); err != nil {
			return err
		}
		if _, err := b.git("push", b.remote, nextVersionTag); err != nil {
			return err
		}
	}
	return nil
}

func (b *BranchManager) PreBranchCutValidation() error {
	branch, err := utils.GitBranch(b.repoRoot)
	if err != nil {
		return err
	}
	if branch != utils.DefaultBranch {
		return fmt.Errorf("not on branch '%s', all new release branches must be cut from %s", utils.DefaultBranch, utils.DefaultBranch)
	}
	if dirty, err := utils.GitIsDirty(b.repoRoot); err != nil {
		return err
	} else if dirty {
		return fmt.Errorf("there are uncommitted changes in the repository, please commit or stash them before creating a new release branch")
	}
	return nil
}

func (b *BranchManager) git(args ...string) (string, error) {
	return command.GitInDir(b.repoRoot, args...)
}