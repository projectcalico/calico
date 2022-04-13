# Contributing to the Calico Codebase

Thanks for considering contributing to Calico! This document outlines the canonical procedure for contributing new features
and bugfixes to Calico. Following these steps will help ensure that your contribution gets merged quickly and
efficiently.

## Overview

### Is this a new feature?

If you'd like to add a new feature to Calico, please first open an issue describing the desired functionality. A Calico
maintainer will work with you to come up with the correct design for the new feature. Once you've agreed on a design, you can then
start contributing code to the relevant Calico repositories using the development process described below.

Remember, agreeing on a design in advance will greatly increase the chance that your PR will be accepted, and minimize the amount of time required
for both you and your reviewer!

### Is this a simple bug fix?

Simple bug fixes can just be raised as a pull request. Make sure you describe the bug in the pull request description,
and please try to reproduce the bug in a unit test. This will help ensure the bug stays fixed!

### Writing, testing, and building the code

For more detailed information on the development process for Calico, see the [developer guide](DEVELOPER_GUIDE.md).

### PR process

Once you've agreed on a design for your bugfix or new feature, development against the Calico codebase should be done using the following steps:

1. [Create a personal fork][fork] of the repository.
1. Pull the latest code from the **master** branch and create a feature branch off of this in your fork.
1. Implement your feature. Commits are cheap in Git; try to split up your code into many. It makes reviewing easier as well as for saner merging.
1. Make sure that existing tests are passing, and that you've written new tests for any new functionality. Each directory has its own suite of tests. 
1. Push your feature branch to your fork on GitHub.
1. [Create a pull request][pulls] using GitHub, from your fork and branch to projectcalico `master`.
    1. If you haven't already done so, you will need to agree to our contributor agreement. See [below](#contributor-agreements).
    1. Opening a pull request will automatically run your changes through our CI. Make sure all pre-submit tests pass so that a maintainer can merge your contribution.
1. Await review from a maintainer.
1. When you receive feedback:
    1. Address code review issues on your feature branch.
    1. Push the changes to your fork's feature branch on GitHub _in a new commit - do not squash!_ This automatically updates the pull request.
    1. If necessary, make a top-level comment along the lines of “Please re-review”, notifying your reviewer, and repeat the above.
    1. Once all the requested changes have been made, your reviewer may ask you to squash your commits. If so, combine the commits into one with a single descriptive message.
    1. Once your PR has been approved and the commits have been squashed, your reviewer will merge the PR. If you have the necessary permissions, you may merge the PR yourself.

#### Patching an older release

If your contribution is intended for an older release, the change will need to be cherry-picked into the appropriate release branch after it has been reviewed
and merged into master. **To make sure this happens, apply the `cherry-pick-candidate` label to the pull request or ask your reviewer to do so.**

Once your reviewer agrees the patch is valid for cherry-picking, perform the following steps to create the cherry-pick PR.

1. Check out the release branch corresponding to your target release, for example: `git fetch upstream; git checkout release-v2.5`.
1. Create the cherry-pick branch based off of the target branch, for example: `git checkout -b cherry-pick-pr12345-v2.5 release-v2.5`
1. Cherry-pick the commit to your new branch: `git cherry-pick [ORIGINAL_COMMIT_HASH]`
1. Push the branch to your fork and create a PR against the appropriate `release-vX.Y` branch.
   - Title the PR `[release-vX.Y] cherry-pick: ORIGINAL_TITLE`
   - In the description, provide a link to the original PR so it can be traced more easily.
   - Make sure the pull request is in the correct GitHub milestone for the next vX.Y.Z release.
   - Make sure to write a release note, and apply the `release-note-required` label to the PR.
1. Notify your original reviewer on the PR.
1. Once your PR is merged, remove the `cherry-pick-candidate` label from the original PR and replace it with `cherry-pick-completed`.

### Release notes and documentation

Most PRs warrant release notes - any bug fixes or new features that users may be interested in. If you are unsure if your PR warrants
a release note in the description, ask your reviewer.

You or your reviewer should make sure that your PR has the correct labels and milestone set.

Every PR needs one `docs-*` label.

- `docs-pr-required`: This change requires a change to the documentation that has not been completed yet.
- `docs-completed`: This change has all necessary documentation completed.
- `docs-not-required`: This change has no user-facing impact and requires no docs.

Every PR needs one `release-note-*` label.

- `release-note-required`: This PR has user-facing changes. Most PRs should have this label.
- `release-note-not-required`: This PR has no user-facing changes.

Other optional labels:

- `cherry-pick-candidate`: This PR should be cherry-picked to an earlier release. For bug fixes only.
- `needs-operator-pr`: This PR is related to install and requires a corresponding change to the operator.

## Contributor Agreements

We need you to sign our Contributor License Agreement before we can accept your
contribution. You will be prompted to do this as part of the PR process
on GitHub.

[fork]: https://help.github.com/articles/fork-a-repo/
[pulls]: https://help.github.com/articles/creating-a-pull-request/
