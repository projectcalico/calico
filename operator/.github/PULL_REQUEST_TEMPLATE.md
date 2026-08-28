## Description

<!-- A few sentences describing the overall goals of the pull request's commits.
Please include
- the type of fix - (e.g. bug fix, new feature, documentation)
- some details on _why_ this PR should be merged
- the details of the testing you've done on it (both manual and automated)
- which components are affected by this PR
- links to issues that this PR addresses
-->

## Release Note

<!-- Writing a release note:

- By default, your PR will be set to require a release note and a docs PR!
- If you do not need a release note, swap the `release-note-required` label for
  the `release-note-not-required` label
- Likewise, if you do not need a docs PR, swap `docs-pr-required` for `docs-not-required`
- If you're not certain if you need a release note or docs PR, please check
  with your reviewer or team lead.

-->

```release-note
TBD
```

## For PR author

- [ ] Tests for change.
- [ ] If changing pkg/apis/, run `make gen-files`
- [ ] If changing versions, run `make gen-versions`

## For PR reviewers

A note for code reviewers - all pull requests must have the following:

- [ ] Milestone set according to targeted release.
- [ ] Appropriate labels:
  - `kind/bug` if this is a bugfix.
  - `kind/enhancement` if this is a a new feature.
  - `enterprise` if this PR applies to Calico Enterprise only.
