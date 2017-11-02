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

### Development process

Once you've agreed on a design for your bugfix or new feature, development against the Calico codebase should be done using the following steps:

1. [Create a personal fork][fork] of the repository to which you'd like to contribute.
1. Pull the latest code from the **master** branch and create a feature branch off of this in your fork.
1. Implement your feature. Commits are cheap in Git; try to split up your code into many. It makes reviewing easier as well as for saner merging.
1. Make sure that existing tests are passing, and that you've written new tests for any new functionality. Each repository has its own suite of tests. See the README for each
   repository for more information on building and running that repository's tests.
1. Push your feature branch to your fork on GitHub.
1. [Create a pull request][pulls] using GitHub, from your fork and branch to projectcalico master.
    1. If you haven't already done so, you will need to agree to our contributor agreement. See [below](#contributor-agreements).
    1. Opening a pull request will automatically run your changes through our CI. Make sure all pre-submit tests pass so that a maintainer can merge your contribution.
1. Await review from a maintainer.
1. When you receive feedback:
    1. Address code review issues on your feature branch.
    1. Push the changes to your fork's feature branch on GitHub _in a new commit - do not squash!_ This automatically updates the pull request.
    1. If necessary, make a top-level comment along the lines of “Please re-review”, notifying your reviewer, and repeat the above.
    1. Once all the requested changes have been made, your reviewer may ask you to squash your commits. If so, combine the commits into one with a single descriptive message.
    1. Once your PR has been approved and the commits have been squashed, your reviewer will merge the PR. If you have the necessary permissions, you may merge the PR yourself.

### Release notes

Some PRs warrant release notes. These are typically important bug fixes or new features that users may be interested in. If unsure if your PR warrants
a release note in the description, ask your reviewer.

## Contributor Agreements

We need you to sign our Contributor License Agreement before we can accept your
contribution. You will be prompted to do this as part of the PR process
on GitHub.

[fork]: https://help.github.com/articles/fork-a-repo/
[pulls]: https://help.github.com/articles/creating-a-pull-request/
