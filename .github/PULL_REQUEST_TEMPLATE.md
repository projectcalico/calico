## Description

<!-- A few sentences describing the overall goals of the pull request's commits.
Please include
- the type of fix - (e.g. bug fix, new feature, documentation)
- some details on _why_ this PR should be merged
- the details of the testing you've done on it (both manual and automated)
- which components are affected by this PR
- links to issues that this PR addresses
-->

## Related issues/PRs

<!-- If appropriate, include a link to the issue this fixes.
fixes <ISSUE LINK>

If appropriate, add links to any number of PRs documented by this PR
documents <PR LINK>
-->

## Todos

- [ ] Tests
- [ ] Documentation
- [ ] Release note

## Release Note

<!-- Writing a release note:
- By default, no release note action is required.
- If you're unsure whether or not your PR needs a note, ask your reviewer for guidance.
- If this PR requires a release note, update the block below to include a concise note describing
  the change and any important impacts this PR may have.
-->

```release-note
TBD
```

## Reminder for the reviewer

Make sure that this PR has the correct labels and milestone set.

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
