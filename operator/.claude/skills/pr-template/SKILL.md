---
name: pr-template
description: Use whenever creating a pull request in this repo (gh pr create, opening a PR, drafting a PR body). The repo requires every PR body to follow .github/PULL_REQUEST_TEMPLATE.md. When creating a PR, ask the user whether they want a release note. Trigger even if the user does not explicitly mention the template.
---

# Use the PR template when creating a PR

This repo enforces `.github/PULL_REQUEST_TEMPLATE.md`. Base every PR body on it,
keeping its section structure (`## Description`, `## Release Note`, checklists).

## Release note: ask, don't assume

When **creating** a PR, ask the user whether they want a release note before opening it:

- **Yes** → put their one-line note inside the fenced block:
  ````
  ```release-note
  <one concise user-facing sentence>
  ```
  ````
- **No** → leave the block as `NONE` and tell the user the `release-note-required`
  label must be swapped for `release-note-not-required` (labels can't be set from the
  PR body). The "Validate Release Notes" check fails until one or the other is done.

When **updating** an existing PR, do NOT ask again — reuse the earlier decision.

## Description

Fill in: type of change, why it should merge, testing done, affected components, and
`Fixes #<issue>` / issue links.

## Gotcha: `gh pr edit` / `gh pr create --body` can fail on this repo

`gh` GraphQL calls hit a deprecated Projects-classic path and error. If editing the
body fails, set it via REST instead (note `-F`, which reads the file contents — `-f`
would upload the literal `@path` string):

```bash
gh pr view <num> --repo tigera/operator --json body --jq .body > /tmp/body.md
# edit the body / release-note block in /tmp/body.md, then:
gh api -X PATCH repos/tigera/operator/pulls/<num> -F body=@/tmp/body.md --jq .body
```
