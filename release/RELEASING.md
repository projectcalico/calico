# Releasing Calico

> [!IMPORTANT]
> These instructions apply only to this branch. For older releases, refer to the
> instructions in the corresponding `release-vX.Y` branch.

This is a runbook. Work through it top to bottom. Each step has:

- **Run:** what to do.
- **Check:** how to tell it worked. Don't move on until it passes.
- **If it fails:** what is safe to do next.

Steps tagged **Manual** need a person: a web UI, a CI button, or a judgement
call.

Commands run from the repo root unless a step says otherwise. Replace `vX.Y.Z`
with the version being released and `release-vX.Y` with its release branch.

## Pick a path

> [!NOTE]
> These are separate tasks, done at different times.

- **Cut a release branch:** once per minor version, ahead of its `vX.Y.0`
  release. See [Cut the release branch](#cut-the-release-branch).
- **Release a version (`vX.Y.0` or a patch):** its `release-vX.Y` branch must
  already exist. See [Release](#release).
- **Build a hashrelease:** a pre-release build of one commit, for testing. See
  [Hashrelease](#hashrelease).

## Cut the release branch

Once per minor version, ahead of its `vX.Y.0` release. This creates
`release-vX.Y` from `master`, plus the dev tags for the next releases.

1. **Run:** see what the cut will do, without acting.

   ```sh
   git checkout master && git pull origin master
   make -C release build
   release/bin/release branch cut --plan
   ```

   **Check:** the plan names `release-vX.Y` and the dev tags you expect.
2. **Run:** cut the branch.

   ```sh
   make create-release-branch
   ```

   **Check:** `git ls-remote --heads origin release-vX.Y` prints the new branch.

   **If it fails:** run it again. Each step checks whether its effect already
   exists and skips it if so. To skip a step on purpose, pass `--skip <step>` to
   `release/bin/release branch cut`; `--help` lists the step names.
3. **Run (Manual):** on the [milestones
   page](https://github.com/projectcalico/calico/milestones), create
   `Calico vX.Y+1.0`. Move the open PRs from `Calico vX.Y.0` into it. Leave
   `Calico vX.Y.0` open.

## Release

Work through these in order.

### Before you start

You need:

- Write access to `projectcalico/calico`, and a GitHub token for it in
  `GITHUB_TOKEN`.
- Push access to the Calico image registries (Quay, Docker Hub, and
  `gcr.io/projectcalico-org` with its regional mirrors).
- For a `vX.Y.0` release: membership of the Project Calico team on Launchpad,
  with an uploaded GPG identity whose secret key you hold.

The official build and publish run in CI, which already holds these credentials.
You need them for the steps you run yourself.

> [!TIP]
> Check these often in the week leading up to the release.

1. **Run (Manual):** clear the milestone. On the [milestones
   page](https://github.com/projectcalico/calico/milestones), create the next
   one (`Calico vX.Y.Z+1`, or `Calico vX.Y+1.0` for a `vX.Y.0` release) if it
   doesn't exist. Merge each open PR in `Calico vX.Y.Z`, or move it and any open
   issue to the next milestone.

   **Check:**

   ```sh
   gh pr list -R projectcalico/calico --search 'milestone:"Calico vX.Y.Z"'
   ```

   This prints nothing.
2. **Run:** confirm no cherry-pick PR for this release is still open.

   **Check:**

   ```sh
   gh pr list -R projectcalico/calico --label cherry-pick-candidate \
     --base release-vX.Y
   ```

   This lists none you need. For a `vX.Y.0` release, use `--base master`.
3. **Run (Manual):** confirm CI is green on the target branch.
4. **Run:** draft the release notes early, so review isn't on the critical path.

   > [!IMPORTANT]
   > Ensure this is done to avoid last-minute delays.
   > See [Release notes](#release-notes) for guidance.

### 1. Prepare the release

1. **Run:**

   ```sh
   git checkout release-vX.Y && git pull origin release-vX.Y
   make release-prep
   ```

   This works out the version from git, generates the release notes, and creates
   `build-vX.Y.Z`. That branch holds one commit: the version bump in charts and
   manifests, `make generate`, and the notes. It then pushes the branch and
   opens a PR against `release-vX.Y`.

   > [!WARNING]
   > `make release-prep` overwrites the release notes, and a rerun drops any
   > commits pushed to `build-vX.Y.Z`. Keep your draft outside the repo.

   **Check:** `gh pr list -R projectcalico/calico --head build-vX.Y.Z` shows the
   PR.

   **If it fails:** fix the cause and run it again. It force-pushes
   `build-vX.Y.Z`.
2. **Run (Manual):** put the final release notes on `build-vX.Y.Z` as a new
   commit. Copy your draft from [Before you start](#before-you-start) over the
   generated file, or edit the generated file directly.

   ```sh
   git switch build-vX.Y.Z
   git add release-notes/vX.Y.Z-release-notes.md
   git commit -m "Update vX.Y.Z release notes"
   git push origin build-vX.Y.Z
   ```

   **Check:** the PR shows the new commit and the notes read as intended.
3. **Run (Manual):** get the PR approved. Do not merge it yet: the release is
   built from this branch.

   **Check:** `gh pr checks <PR number> -R projectcalico/calico` shows every
   check passing.
4. **Run (Manual):** for a `vX.Y.0` release only, create a Calico X.Y.x PPA in
   Launchpad.

### 2. Build and publish

1. **Run (Manual):** in CI, find the head commit of `build-vX.Y.Z`. Confirm its
   tests passed. Then start the official release job on it ("Publish official
   release"). The job runs `make release`, `make release-publish`, then
   `make publish-openstack`.

   **Check:**
   - The job passed.
   - `gh release view vX.Y.Z -R projectcalico/calico` shows a draft release with
     its assets.
   - `docker buildx imagetools inspect quay.io/calico/calico:vX.Y.Z` finds the
     image.

   **If it fails:** fix the cause and run the job again on the same commit.
   Publish is safe to repeat: it skips what is already published.

### 3. Publish the GitHub release

1. **Run (Manual):** publish the draft. Mark it latest only if `vX.Y` is the
   newest minor series.

   ```sh
   gh release edit vX.Y.Z -R projectcalico/calico \
     --draft=false --latest=<true|false>
   ```

   **Check:** `gh release view vX.Y.Z -R projectcalico/calico --json isDraft`
   prints `"isDraft": false`.

### 4. Merge the release PR

1. **Run (Manual):** merge the `build-vX.Y.Z` PR with a merge commit, then
   delete the branch.

   > [!WARNING]
   > Do not use "Squash and merge". The `vX.Y.Z` tag sits on the `build-vX.Y.Z`
   > commit. A squash leaves that commit, and so the tag, out of `release-vX.Y`.

   **Check:**

   ```sh
   git fetch origin --tags
   git merge-base --is-ancestor vX.Y.Z origin/release-vX.Y && echo ok
   ```

   This prints `ok`.

### After the release

1. **Run (Manual):** close the `Calico vX.Y.Z` milestone. Move anything still
   open in it to the next milestone first.
2. **Run (Manual):** in CI, start the post-release job for tag `vX.Y.Z` (or
   branch `build-vX.Y.Z`). It runs `make postrelease-checks`.

   **Check:** the job passed. If a test failed, find out why before calling the
   release done.
3. **Run (Manual):** start e2e tests against the released version.
4. **Run:** update the `projectcalico/api` repository to match this release.

   ```sh
   git clone git@github.com:projectcalico/api.git && cd api
   git checkout -b release-vX.Y && git push origin release-vX.Y   # vX.Y.0 only
   git checkout release-vX.Y && git pull origin release-vX.Y      # patches
   make -f Makefile.local pr CALICO_GIT_REF=vX.Y.Z
   ```

   This imports the API files from `projectcalico/calico` at `vX.Y.Z` and opens
   a PR. It needs the [GitHub CLI](https://github.com/cli/cli#installation).

   > [!NOTE]
   > If an auto-api PR for this version already exists, the command prints an
   > error but still updates that PR.

   **Check (Manual):** the PR is reviewed and merged.

### Release notes

`make release-prep` generates the notes. To draft them earlier, run:

```sh
make release-notes
```

This needs `GITHUB_TOKEN` set and writes
`release-notes/<VERSION>-release-notes.md`.

A merged PR's note is included only if the PR:

- is in the `Calico vX.Y.Z` milestone,
- has the `release-note-required` label, and
- has a release note in its description.

To check, list the milestone's PRs:

```sh
gh pr list -R projectcalico/calico --state merged \
  --search 'milestone:"Calico vX.Y.Z"'
```

The generated file opens with the date and two placeholder headings,
`#### Headline feature 1` and `#### Headline feature 2`. Every PR then lands
under `#### Other changes`, one line each with its link and author, and
`#### Bug fixes` is left empty. When editing:

- For a `vX.Y.0` release, replace the placeholders with one
  `#### Headline features` heading. Give each major feature a `#####` heading
  that links its PR, and a short paragraph on what it does for users.
- Say in that paragraph if the feature breaks, deprecates, or changes existing
  behaviour, or needs a step before a downgrade.
- For a patch, delete the placeholders.
- Move each bug fix from `Other changes` to `Bug fixes`. Fix wording, not
  layout.

For the expected format, see the [v3.33.0 notes
(minor)](https://github.com/projectcalico/calico/blob/release-v3.33/release-notes/v3.33.0-release-notes.md)
and the [v3.32.2 notes
(patch)](https://github.com/projectcalico/calico/blob/release-v3.32/release-notes/v3.32.2-release-notes.md).

## Hashrelease

A hashrelease is a build of one commit, named by its git hash, for testing
before a release. CI builds one on a schedule and publishes it to the
hashrelease server; that needs nothing from you. This section is for building
one yourself and pushing it to your own registries, for example to test a change
to the release code.

### What you need

- Your own image registry, with `docker login` done.
- Your own Helm chart registry, with `helm registry login` done.
- Optionally, a GitHub token in `GITHUB_TOKEN` or from `gh auth login`. The
  build reads PRs from GitHub to write release notes, and requests without a
  token are rate-limited. To skip the notes, add `--no-release-notes`.

You don't need write access to `projectcalico/calico`.

> [!WARNING]
> Use your own registries, not the Calico ones. Without `--registry`,
> `--operator-registry` and `--helm-registry`, publish pushes to the Calico
> registries.

### Flags

`--help` lists most on/off flags as `--[no-]<name>`, with a default. `--<name>`
turns one on and `--no-<name>` turns it off. Each also reads the environment
variables shown beside it. The ones a hashrelease run most often needs:

- `--images`: images are off by default for a hashrelease. Add this to build and
  publish them.
- `--no-validation`: skips checks a CI run needs, such as being on a release
  branch.
- `--no-publish-to-hashrelease-server`: the server is on by default. Add this
  unless you are publishing to it, which also needs
  `--hashrelease-server-bucket`.
- `--no-latest`: publishing to the hashrelease server marks the hashrelease as
  latest by default. Only CI may do that, so add this when you publish to the
  server yourself.
- `--no-release-notes`: skips the release notes.

### Build and publish

Commands run from `release/`, after `make build`.

> [!TIP]
> Check a command's `--help` before copying an example. It lists the flags this
> build accepts.

1. **Run:** build it. `--operator-registry` is required whenever `--registry` is
   set. See [Flags](#flags) for the others.

   ```sh
   ARCHS=amd64 ./bin/release hashrelease build --no-validation --images \
     --registry <YOUR REGISTRY> --operator-registry <YOUR REGISTRY>
   ```

   **Check:** the release images, an operator image, and `_output/hashrelease`
   exist.
2. **Run:** publish it to your own registries, without the hashrelease server or
   the image scan.

   ```sh
   ./bin/release hashrelease publish --no-validation --images \
     --registry <YOUR REGISTRY> --operator-registry <YOUR REGISTRY> \
     --helm-registry <YOUR HELM REGISTRY> \
     --no-publish-to-hashrelease-server --no-image-scan
   ```

## Dry runs with `--local`

`--local` runs local work as normal and turns every remote change (push, upload,
tag) into a dry run. Reads still happen. Add it to any `build`, `publish`,
`prep` or `branch cut` command to check a run before it touches anything remote.
