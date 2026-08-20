# Calico packaging — design

This file describes the design of `release/packaging`: a Makefile-driven build
and publish pipeline for the Calico `.deb` and `.rpm` packages, which replaced a
single-shell-script orchestrator.

Operational guidance (how to run it) lives in [`README.md`](README.md).
This file records *what the pipeline promises* and *why it is shaped this way*.

---

## 1. Why it changed

`utils/create-update-packages.sh` (340 lines) used to be the whole pipeline. It
held the component list, the version arithmetic, the per-component build
quirks, the platform matrix, the publish sequencing, and the precondition
checks. `make` was a two-line wrapper that set `PUBLISH=true` or not.

The problems it had, which the rest of this file is the answer to:

| Problem | Consequence |
|---|---|
| `STEPS` is a hand-rolled sequencer with `eval "do_${step}"` | No dependency graph, no resume, no `-j`, no dry-run |
| `rm -rf output/` on every invocation | Every run is a full rebuild; a failed publish means rebuilding everything |
| Build and publish are one target gated by `PUBLISH=true` | Cannot re-publish without rebuilding, and cannot build without publish credentials in scope |
| Packages are built by mutating the working tree (`sed -i setup.py`, `rm -f debian/changelog`, `patchelf bin/calico-felix`, `git checkout setup.py`) | Builds are order-dependent (RPM *must* precede deb for Felix), not parallelisable, and leave the tree dirty on failure |
| Two divergent exclude lists per component (`RPM_TAR_ARGS`, `DPKG_EXCL`) | Exists only because we tar up a dirty working tree |
| Ubuntu publishing uploads *source* packages and waits on Launchpad (~1h, sometimes many hours) | No way to get an installable `.deb` locally, and no pre-upload validation |
| Nothing verifies the packages install | The `libpcap.so.1` vs `libpcap.so.0.8` class of bug is only found by users |
| The Launchpad signing key must be a standalone file on disk | Awkward locally, and duplicates a key the developer already has in their keyring |

## 2. Design principles

1. **Makefiles hold policy; scripts hold mechanism.** What to build, for which
   platform, in what order, with which flags — Makefile. "Sign this one
   `.changes` file", "check this ELF" — a short script that does one thing,
   takes arguments, and has no knowledge of the component list.
2. **Targets are files, not verbs.** The artifacts on disk are the state.
   Re-running a target that already produced its file is a no-op. This gives
   resume-after-failure and `-j` for free.
3. **Never mutate the source tree.** Each `(component, platform)` build runs
   against a staging copy under `output/`. The working tree is read-only input.
4. **Build, publish, and test are independent phases** that can be run
   separately, in one `make` invocation, or across separate CI jobs.
5. **No key material under `output/`.** CI artifact-pushes that directory
   (`.semaphore/release/release.yml`).

## 3. Directory layout

```
release/packaging/
├── Makefile                     # entry point; includes mk/*.mk
├── mk/
│   ├── config.mk                # tunables, defaults, version derivation
│   ├── components.mk            # the component table (the "what to build")
│   ├── images.mk                # build-container images
│   ├── felix-el8.mk             # calico-felix, built against the oldest glibc
│   ├── build-ubuntu.mk          # .dsc/.changes source packages
│   ├── build-rhel.mk            # .rpm
│   ├── binaries.mk              # .dsc to .deb
│   ├── publish-ubuntu.mk        # dput to Launchpad PPA
│   ├── publish-rhel.mk          # GAR + binaries.projectcalico.org
│   └── test.mk                  # install-and-verify in clean containers
├── utils/                       # single-purpose scripts, all argv-driven
├── docker-bake.hcl              # build-image definitions; context is this dir
├── docker-build-images/         # the Dockerfiles and their install scripts
├── .dockerignore                # keeps output/ out of the build context
├── rpm/build-rpms               # runs inside the EL build container
└── output/                      # all generated state (gitignored)
```

`utils/lib.sh` and `utils/create-update-packages.sh` are deleted;
`make-packages.sh`, `publish-debs.sh` and `publish-rpms.sh` are replaced by the
per-item scripts in section 7.

### Output tree

```
output/
├── felix-el8/bin/calico-felix   # the felix binary every package ships
├── felix-el8/libbpf/<arch>/     # libbpf.a rebuilt against EL 8's glibc
├── src/<series>/<pkg>/          # staging copy for one deb source build
├── src/rpm/<pkg>/               # staging copy for the rpm build
├── <pkg>_<debver>-<series>_source.changes    # deb source package (+ .dsc, .tar.xz)
├── <pkg>_<debver>-<series>_source.ppa.upload # created by dput == "uploaded" stamp
├── binaries/<series>/*.deb      # binary debs from section 5.3
├── dist/rpms-el8/{,src,noarch,x86_64}/*.rpm  # the RPM output path CI archives
├── .launchpad/<series>.sources  # what the PPA already has (section 5.4)
└── .stamps/                     # stamps for steps with unpredictable filenames
    ├── prepare-<pkg>            # the component binaries the packages ship
    ├── rpm-<pkg>-el<n>
    └── binaries-<series>
```

`output/dist/rpms-el<n>` is where `rpm/build-rpms` writes from inside the
container, and `release.yml` archives the whole tree as the release artifact.

The component name is the *last* element of a staging path, because both
`dpkg-source` and `rpm/build-rpms` name what they produce after the directory
they are run in: a `.tar.xz` whose top-level directory is `felix/`, as today,
rather than `noble/`.

## 4. The component table

All per-component knowledge moves into `mk/components.mk` as data:

Field names are prefixes and the component name is the suffix — `DIR_felix`,
not `felix_DIR` — so that a rule can look a field up as `$(DIR_$(pkg))` without
nesting one variable reference inside another.

```make
COMPONENTS := networking-calico felix calicoctl

DIR_networking-calico        := $(REPO_ROOT)/networking-calico
NAME_networking-calico       := networking-calico
DEB_EPOCH_networking-calico  := 3:
PLATFORMS_networking-calico  := ubuntu rhel
STAGE_HOOK_networking-calico := $(UTILS)/set-python-version

DIR_felix            := $(REPO_ROOT)/felix
NAME_felix           := Felix
DEB_EPOCH_felix      := 3:
PLATFORMS_felix      := ubuntu rhel
PREPARE_felix        := $(STAMP_DIR)/prepare-felix   # el8 binary + BPF objects
STAGE_HOOK_felix      = $(UTILS)/install-staged-file $(FELIX_EL8_BINARY) bin/calico-felix
DEB_STAGE_HOOK_felix := $(UTILS)/patch-felix-libpcap
EXCLUDES_felix       := bin/calico-felix bin/calico-felix-* bpf-gpl/bin/test_* \
                        .git .gitignore *.d *.ll .go-pkg-cache vendor report

DIR_calicoctl       := $(REPO_ROOT)/calicoctl
NAME_calicoctl      := calicoctl
PLATFORMS_calicoctl := ubuntu rhel
PREPARE_calicoctl   := $(STAMP_DIR)/prepare-calicoctl
EXCLUDES_calicoctl  := bin/calicoctl-* .git .gitignore .go-pkg-cache \
                       report test-data tests
```

Notes on what this table changes:

- **One `EXCLUDES_` list replaces `RPM_TAR_ARGS` and `DPKG_EXCL`.** The Makefile
  renders it into `rsync --exclude=` flags when populating the staging dir. The
  two formats existed only because the RPM path tarred the tree and the deb path
  passed `-I` flags to `dpkg-buildpackage`; once both build from a clean staging
  copy, one list suffices and they cannot drift. The merged list also carries
  `bpf-gpl/bin/test_*`, which today is handled by deleting those files from the
  Felix build output — the RPM `%files` and `debian/rules` both install
  `bpf-gpl/bin/*`, so the unit-test objects have to be excluded somewhere.
- **`PREPARE_`** names a target that must run before staging (building
  `bin/calico-felix`, `bin/calicoctl`). It is a *stamp file*
  rather than a phony target, for two reasons: a phony prerequisite would make
  every package look out of date on every run, and one stamp is shared by all
  the series and formats that build from it. The stamp lives under `output/`, so
  `make clean` forces the binaries to be rebuilt.
- **`STAGE_HOOK_`/`DEB_STAGE_HOOK_`** are the per-component fixups that used to
  be `if [ "${PKG_NAME}" = ... ]` branches inside `make-packages.sh`: stamping
  the version into `setup.py`, the Felix `patchelf`, and installing the Felix
  binary from section 4.1. The Makefile appends `<stagedir> <version>` to
  whatever the field holds, so a hook can carry arguments of its own and can only
  affect the staging copy.
- **Two components are gone**, both of which existed only for CentOS/RHEL 7.
  `dnsmasq` we built ourselves because CentOS 7 was stuck on 2.76 and our upstream
  patches need 2.79; EL 8 ships 2.79. `etcd3gw`'s spec built Python 2 packages,
  which EL 8 cannot; the answer there is now the one Ubuntu always had,
  `pip install etcd3gw`. Both leave a comment in `mk/components.mk` recording
  what they were and where to find the dnsmasq fork.

Adding a component becomes: add a stanza, add it to `COMPONENTS`. No new rules.

### 4.1 The Felix binary is built here, not taken from felix/bin

`mk/felix-el8.mk` builds its own `calico-felix` and every package gets that one.
It exists because of glibc symbol versioning:

| built in | glibc | binary runs on |
|---|---|---|
| `calico/go-build` (AlmaLinux 9) | 2.34 | jammy, noble, EL 9+ |
| this pipeline's el8 image | 2.28 | focal, jammy, noble, EL 8+ |

A binary from `calico/go-build` cannot run on the oldest platforms we publish to:
on EL 8 the RPM's generated `Requires: libc.so.6(GLIBC_2.34)` is unsatisfiable,
and on Ubuntu 20.04 the `.deb` installs and then the binary will not start. A
binary built against the *oldest* glibc runs everywhere newer, so the packaged
one is built in the EL 8 image — the oldest distribution we package for.

Three parts, mirroring `node/Makefile.rhel8` in calico-private, which does the
same thing for calico-node's RHEL 8 RPM:

1. **`libbpf.a` is rebuilt** in the el8 image, into `output/felix-el8/libbpf/`
   rather than `felix/bpf-gpl/libbpf/src/<arch>/`. Linking the go-build archive
   would put its glibc references straight back into the binary, and writing to
   felix's own objdir would silently change what another build links.
2. **The cgo binary is rebuilt** in the same image, with `CGO_LDFLAGS` pointed at
   that archive. Its `-ldflags` are asked of felix's own makefile rather than
   copied into this one, so the packaged binary carries the same buildinfo stamps
   as every other build of Felix and cannot drift from them.
3. **The BPF programs are reused as-is** from felix's normal `make build-bpf`:
   clang emits kernel bytecode, which has no libc to link against.

The binary reaches the packages as a staging hook — `install-staged-file` — and
`bin/calico-felix` is in `EXCLUDES_felix`, so a stray binary in a developer's
`felix/bin/` can never end up in a package instead.

The el8 image therefore does two jobs: it builds the RPMs *and* it builds this
binary. That is deliberate — the image that defines our oldest supported EL is
exactly the right place to define our glibc floor.

`mk/felix-el8.mk` and its `include` line should be deleted once every platform we
package for has a glibc at least as new as `calico/go-build`'s.

## 5. Target graph

```
build ─┬─ build-ubuntu ──── build-ubuntu-<pkg>       (× series)
       └─ build-rhel ────── build-rhel-<pkg>         (× EL version)

build-binaries ──────────── build-binaries-<series>   [reads build-ubuntu output]

publish ─┬─ publish-ubuntu ─ (dput each *_source.changes)
         └─ publish-rhel ─┬─ publish-rhel-gar
                          └─ publish-rhel-bpo

test ────┬─ test-ubuntu ──── test-ubuntu-<series>     [reads build-binaries output]
         └─ test-rhel ────── test-rhel-el<n>          [reads build-rhel output]

images ──┬─ images-ubuntu ── images-ubuntu-<series>  (calico-build/<series>)
         └─ images-rhel ──── images-rhel-el<n>       (calico-build/el<n>)

clean            # rm -rf output/
```

Aggregates (`build`, `publish`, `test`, and so on) are `.PHONY`. Everything
below them resolves to files, except the image targets: what they produce lives
in docker's image store rather than in `output/`, so they always run and rely on
buildx's cache to be cheap. Anything that needs an image takes it as an
*order-only* prerequisite, so a rebuilt image never invalidates a package that
has already been built.

**How the per-component rules are generated.** Each format has exactly one
recipe, written as a static pattern rule over the list of artifacts that the
component table implies. The recipe reads the component and the platform back
out of the target name — the stem of `output/felix_3.31.0-noble_source.changes`
gives both — and looks up the rest of the table with `$(DIR_$(deb_pkg))` and
friends. `.SECONDEXPANSION:` lets the prerequisite list do the same, which is
how each artifact gets its own component's `PREPARE_` and its own series' image.

The alternative — a `foreach` over the table `eval`ing a rule template per pair
— generates one copy of the recipe per artifact. One static rule keeps the
recipe in a single place, keeps `make --debug` and `make -p` output legible, and
means a mistake in the recipe cannot show up in some instantiations and not
others.

`publish-rhel-bpo` is the `binaries.projectcalico.org` RPM repo
(scp + `repomanage` + re-sign + `createrepo`). `publish-rhel-gar` is the Google
Artifact Registry yum repo. They are independent and can run in either order or
in parallel; `publish-rhel` runs both and fails if either fails. Today the GAR
upload is deliberately last "as it wants to `exit 1` if uploads failed. It's a
hack, but it works"; making them siblings removes the hack.

### 5.1 `build-ubuntu` — deb source packages

One target per `(component, series)` pair — the `.changes` file — and one rule
covering all of them. Resolved for Felix on noble, it does:

```make
output/felix_$(DEB_VERSION)-noble_source.changes: output/.stamps/prepare-felix \
                                                | output images-ubuntu-noble
	utils/stage-source $(DIR_felix) $(STAGE) '$(EXCLUDES_felix)'
	utils/patch-felix-libpcap $(STAGE) $(PEP440_VERSION)
	utils/write-deb-changelog $(STAGE) felix 3:$(DEB_VERSION)-noble noble \
	                          '$(CHANGELOG_MESSAGE)'
	docker run --rm --user $(DOCKER_USER) -v output/src/noble:/code -w /code/felix \
	                          calico-build/noble dpkg-buildpackage -I -S -d -us -uc
	mv output/src/noble/felix_$(DEB_VERSION)-noble* output/
```

The container's `/code` is the *parent* of the staging copy, because that is
where `dpkg-buildpackage` writes the `.dsc`, `.tar.xz` and `.changes`; the recipe
then moves them up into `output/`.

Key changes from today:

- **No `-I` at all.** `dpkg-source` excludes nothing unless it is asked to, and a
  bare `-I` — the old `networking-calico` invocation — *adds* its default ignore
  list, which drops `*.o`, `.git*`, `*.a` and more. That list is why the old code
  passed a hand-built `-I<pattern>` list for Felix and calicoctl: they need their
  binaries and BPF objects in the package. Since the staging copy is now exactly
  the file set we want, every exclude belongs there and none belongs on the
  command line. Per-package `debian/source/options` still applies, and is
  unaffected.

  `networking-calico` therefore gains `.gitignore` in its excludes: it is the one
  file in that tree the default list used to drop.

- **The changelog is written into the staging copy**, so the three series no
  longer race over one `debian/changelog` and `-j3` is safe.
- **`networking-calico`'s `sed -i setup.py`** is applied to the staging copy, so
  the `git checkout setup.py` cleanup disappears along with the failure mode
  where a crashed build leaves the tree dirty.
- **Felix's `patchelf --replace-needed libpcap.so.1 libpcap.so.0.8`** is applied
  to the staging copy's `bin/calico-felix`, not the shared one. This removes the
  "build RPM before deb" ordering constraint, which today exists *only* because
  the deb path mutates a binary the RPM path also reads. The Felix prepare
  target produces one pristine binary; each consumer patches its own copy.
- `-us -uc` is explicit: signing happens at publish time, not build time.

### 5.2 `build-rhel` — RPMs

Same shape, one target per `(component, EL version)`, all writing into
`output/dist/rpms-el<n>/`. The container invocation and `rpm/build-rpms` are
unchanged. The spec-file templating (`.spec.in` to `.spec`,
`Version:`/`Release:`/`%changelog`) moves out of `make-packages.sh` into
`utils/write-rpm-spec`, called with the staging dir and the computed version, and
writes into the staging copy. A component that ships a ready-made `.spec` instead
of a template has no `.spec.in`, and for that one it is a no-op.

The container invocation is the same shape as today's: the repo root at `/code`,
because that is where `build-rpms` writes its output, and the working directory
set to the tree to package — now the staging copy under
`output/src/rpm/<pkg>/` instead of the component's own directory.

Because RPM filenames are derivable but tedious (epoch, `%{dist}`, sub-packages),
these targets use a stamp file, `output/.stamps/rpm-<pkg>-el<n>`, rather than
naming every produced RPM.

`EL_VERSIONS := 7` stays a variable so adding EL8/EL9 is a one-line change.

### 5.3 `build-binaries` — source deb to binary deb (new)

Reuses the `calico-build/<series>` images, which already carry the
`Build-Depends` — that is what `install-ubuntu-build-deps` installs. Per series,
one stamp target depending on that series' `.dsc` files, whose recipe runs
`utils/build-binary-debs <series>` inside the build image.

`utils/build-binary-debs` runs, per `.dsc`:

```
dpkg-source -x <pkg>.dsc  binaries/<series>/<pkg>/
cd binaries/<series>/<pkg> && dpkg-buildpackage -b -uc -us
```

`.deb` files land in `output/binaries/<series>/`.

This is what makes the test phase possible, and it validates the source package
*before* we hand it to Launchpad. Today a source package that fails to build is
only discovered an hour later in the PPA's build log. If a build image ever
lacks a declared build dependency, the script falls back to `mk-build-deps -ir`
inside the container rather than failing opaquely.

These binary debs are **not** published: Launchpad builds the official ones, so
that they are built in the PPA's own environment and signed by Launchpad. Ours
are for local install, local testing, and CI gating.

### 5.4 `publish-ubuntu`

One target per `.changes` file. `dput` already writes `<base>.ppa.upload` on
success, so that file *is* the make stamp. Re-running skips completed uploads
with no extra bookkeeping:

```make
$(DEB_UPLOAD_STAMPS): $(OUTPUT_DIR)/%.ppa.upload: $(OUTPUT_DIR)/%.changes \
                          | $(LAUNCHPAD_INDEX) check-ppa
	utils/publish-deb-source $< ppa:project-calico/$(REPO_NAME) $(LAUNCHPAD_INDEX)
```

`$(LAUNCHPAD_INDEX)` is `output/.launchpad/<series>.sources`, a downloaded and
decompressed `Sources.gz` per series. `publish-deb-source` consults it and exits
0 without uploading if Launchpad already has that package and version — creating
the `.ppa.upload` stamp itself in that case, so the skip is remembered. This
replaces today's `.previously-uploaded` sentinel-file dance with a plain lookup.

`check-ppa` is today's precheck: a `curl -I` of the PPA page, with the same "go
and create it" message, which remains the one manual step in the process.

`publish-deb-source` handles exactly one file and owns its own key material for
the duration of that one upload: it creates a private temporary directory with
`mktemp -d`, registers a `trap ... EXIT` to remove it, obtains the signing key,
then runs `debsign` and `dput` in the `calico-build/<series>` container as
today. Nothing is written under `output/`.

### 5.5 `test` — install verification (new, optional)

Not part of `build` or `publish`. Run explicitly, or wired into CI as a gate
between them.

**`test-ubuntu-<series>`** runs in a stock `ubuntu:<series>` image — not the
build image, which has dev packages installed and would mask a missing runtime
dependency:

```
apt-get update
apt-get install -y /output/binaries/<series>/*.deb
utils/check-installed-package <pkg>...
```

The package names come from the `.deb` files themselves (`dpkg-deb -f`), so the
component table needs no second list of binary package names.

**`test-rhel-el<n>`** runs in a stock `almalinux:<n>` image, for the same reason:
the build image has the `-devel` packages and a Go toolchain installed and would
hide a missing runtime dependency.

```
dnf install -y <the RPMs named by RPM_TEST_PACKAGES>
utils/check-installed-package <pkg>...
```

Here the package list *is* configuration: `calico-compute` and `calico-control`
require `openstack-neutron`, which a stock EL image has no repository for, so
`RPM_TEST_PACKAGES` defaults to the packages that ship ELF objects — the ones the
check has something to say about.

`utils/check-installed-package` is the one script both paths call. For each
named package it lists the installed files (`dpkg -L` or `rpm -ql`), selects the
ELF objects, and fails on:

- `ldd -r` output containing `not found`, meaning a missing shared library
- `ldd -r` output containing `undefined symbol`, meaning an ABI mismatch
- a non-zero exit from the binary's own version command

Version commands are an allowlist inside the script (`calico-felix --version`,
`calicoctl version --client`), not a guess: running an arbitrary installed
program — a daemon, say — is not a smoke test. Anything not on the list gets the
library checks alone.

This is the check that would have caught the `libpcap.so.1` versus
`libpcap.so.0.8` soname mismatch that the Felix `patchelf` hack works around.

## 6. Configuration

`mk/config.mk`. All `?=` so the environment and command line still win, which
keeps every current CI invocation working.

```make
# --- publishing endpoints -------------------------------------------------
GCLOUD_ZONE     ?= us-east1-c
GCLOUD_PROJECT  ?= tigera-wp-tcp-redirect
GCLOUD_ARGS     ?= --zone $(GCLOUD_ZONE) --project $(GCLOUD_PROJECT)
HOST            ?= ubuntu@binaries-projectcalico-org
GAR_LOCATION    ?= us-west1
RPM_REMOTE_DIR  ?= /usr/share/nginx/html/rpm

# --- signing --------------------------------------------------------------
SECRET_KEY_ID   ?=          # preferred: a key id/fingerprint/uid in your keyring
SECRET_KEY      ?=          # legacy: path to a standalone key file
SECRET_KEY_PASSPHRASE_FILE ?=

# --- what to build --------------------------------------------------------
VERSION         ?= master
UBUNTU_SERIES   ?= focal jammy noble
EL_VERSIONS     ?= 7
ARCH            ?= amd64
PACKAGE_ETCD3GW ?=

# --- other ----------------------------------------------------------------
PPA_OWNER            ?= project-calico
RPM_SIGNING_KEY_NAME ?= Project Calico Maintainers
RPM_TEST_PACKAGES    ?= calico-common calico-felix calicoctl
DOCKER_USER          ?= $(shell id -u):$(shell id -g)
FORCE_VERSION        ?=   # and DEB_VERSION / RPM_VERSION, each overridable alone
```

`GCLOUD_ARGS` and `HOST` get real defaults, so a local run needs no environment
setup for the RHEL side. `GCLOUD_ARGS` stays overridable as a single string for CI
compatibility, but is now *composed* from `GCLOUD_ZONE` and `GCLOUD_PROJECT` —
and `GCLOUD_PROJECT` is the same variable the GAR upload already uses, so the
project name stops being spelled out twice.

`REPO_NAME` and `GCLOUD_REPO_NAME` derivation from `VERSION` (the `master`,
`release-v*`, `pr-N` and `vX.Y.Z` cases, plus GAR's no-periods rule) moves from
`require_version` into `mk/config.mk` as Make conditionals, about 20 lines. Only
the two "is this all digits?" tests are shelled out, because Make cannot express
them.

The version arithmetic goes the same way. `utils/git-auto-version` prints the
PEP 440 version and is the one place git is consulted; the Debian and RPM
spellings of it (`~rc` for Debian's sort order, `_` plus a `Release:` qualifier
for RPM) are `$(subst ...)` in `mk/config.mk`. `make print-config` shows the lot,
which is how you check what a `VERSION=` value will produce before running
anything.

Goals that cannot need a version — `clean`, `help`, the image targets — skip the
git lookup entirely, so `make clean` works in a shallow clone.

### 6.1 Signing: `SECRET_KEY_ID`

The preference is `SECRET_KEY_ID` over `SECRET_KEY`. Resolution order:

1. `SECRET_KEY` set and readable — use that file. This is the legacy path; CI
   keeps working unchanged and Semaphore's `$HOME/secrets/marvin.txt` needs no
   migration.
2. `SECRET_KEY_ID` set — take the key from the invoking user's local GnuPG
   keyring at use time.
3. Neither — `publish-ubuntu` fails with a message naming both variables.
   Nothing else fails: `build`, `build-binaries`, `test`, and both
   `publish-rhel` targets never touch the Launchpad key.

`utils/export-secret-key <key-id> <dest-file>` is a five-line wrapper around
`gpg --export-secret-keys` that writes the named key, in armored form, to the
destination path under `umask 077`, then checks the result is non-empty. The
Makefile never calls it directly — only `publish-deb-source` does, into the
temporary directory it already owns and cleans up.

Design points:

- **Pinentry is left enabled by default.** The default invocation omits
  `--pinentry-mode loopback`, so gpg-agent prompts normally for a protected key,
  which is the right local behaviour. Setting `SECRET_KEY_PASSPHRASE_FILE`
  switches on loopback mode with `--passphrase-file` for unattended use.
- **The extracted key exists only for the duration of one upload**, in a
  `mktemp -d` directory with mode 0700, removed by an `EXIT` trap, outside
  `output/`.
- **`debsign -k$(SECRET_KEY_ID)`** replaces today's `debsign -k'*@'` when an ID
  is available, so a keyring holding several keys signs with the intended one
  instead of whichever matches first.
- We extract the one key rather than mounting `$GNUPGHOME` or the agent socket
  into the container: the container runs as a different uid, agent sockets do
  not survive a bind mount across the container boundary reliably, and mounting
  the whole keyring would expose every private key you own to the container
  rather than just the signing one.

## 7. Scripts after the refactor

Each takes its inputs as arguments, does one thing, and knows nothing about the
component list or the platform matrix.

| Script | Arguments | Does |
|---|---|---|
| `stage-source` | srcdir, destdir, excludes | `rsync -a --delete` a clean build copy |
| `write-deb-changelog` | stagedir, pkg, version, series, message | `dch --create --release` |
| `write-rpm-spec` | stagedir, version, release, message | `.spec.in` to `.spec` plus a `%changelog` stanza |
| `set-python-version` | stagedir, version | stamp the version into `setup.py` |
| `patch-felix-libpcap` | stagedir | `patchelf` the staged `bin/calico-felix` |
| `build-binary-debs` | series | `dpkg-source -x` plus `dpkg-buildpackage -b` per `.dsc` |
| `export-secret-key` | key-id, dest | pull one key out of the local keyring |
| `publish-deb-source` | changes-file, ppa, sources-index | skip-if-present, sign, `dput` |
| `publish-rpm-to-gar` | rpm-file, repo | skip-if-present, `gcloud artifacts yum upload` |
| `refresh-rpm-repo` | repo, remote-dir, key-name | print the remote re-sign plus `repomanage` plus `createrepo` script |
| `check-installed-package` | pkg... | `ldd -r` plus smoke test the installed ELFs |
| `install-staged-file` | source, dest-in-stage, stagedir | put a prebuilt file into a staging copy |
| `git-auto-version` | none | PEP 440 version from git state |
| `rpm/build-rpms` | none | tar the staged source, then `rpmbuild -ba` |

The staging hooks (`set-python-version`, `patch-felix-libpcap`,
`install-staged-file`) are named in the component table rather than called from a
rule, which is what keeps per-component quirks out of the recipes.

Deleted: `create-update-packages.sh`, `make-packages.sh`, `publish-debs.sh`,
`publish-rpms.sh`, `lib.sh`.

`lib.sh`'s `ssh_host` and `scp_host` become recipe lines in
`mk/publish-rhel.mk`; its `update_repo_metadata` heredoc becomes
`utils/refresh-rpm-repo`, piped to `gcloud compute ssh`. `lib.sh`'s
`validate_version` and `test_validate_version` are dead code — nothing calls
them — and go away with it.

## 8. Invariants

Things a change to this directory must not break:

1. **`output/dist/rpms-el<n>/` is the RPM output path.** `rpm/build-rpms` writes
   it from inside the container and `.semaphore/release/release.yml` archives
   the whole `output/` tree as the release artifact.
2. **The source tree is never modified by a build.** No `sed -i`, `patchelf`, or
   `rm` outside `output/`. `git status` is clean after any target, including
   after a failure. The prepare targets writing `bin/` in a component are the
   one exception, and those are that component's own normal build output.
3. **No key material is written under `output/`.**
4. **Every target is idempotent.** Re-running after success is a no-op;
   re-running after a partial failure resumes.
5. **Publishing is skip-if-already-present, per artifact.** Launchpad rejects
   duplicate source uploads and GAR rejects duplicate versions, so both publish
   paths must check first and skip, not fail.
6. **Build never needs a signing key, and publishing an artifact never rebuilds
   it.** A publish target consumes a built file: if it is there, it is uploaded
   as it stands, so re-publishing after a failure costs no rebuild. (Make will
   still build an artifact that is *absent*, which is how `make build publish` in
   one invocation works.)
7. **`REPO_NAME` and `GCLOUD_REPO_NAME` are derived in exactly one place**
   (`mk/config.mk`), because GAR forbids the periods that the PPA name uses.

## 9. Migration

The refactor landed in one PR; CI moves in a second, so step 4 below is still
outstanding.

1. **Compatibility aliases.** `release:` maps to `build` and
   `release-publish:` to `build publish`, so
   `.semaphore/push-images/packaging.yaml` and the root `Makefile`'s
   `build-openstack` and `publish-openstack` keep working untouched. `STEPS` and
   `PUBLISH` are dropped; nothing in-repo sets them, and
   `.semaphore/push-images/packaging.yaml` records that Semaphore-specific step
   selection was already moved out of the script.
2. **`clean` is no longer implicit.** `create-update-packages.sh` started with
   `rm -rf output/`. Incremental builds require dropping that, so the
   compatibility `release:` alias runs `clean` and then `build` to preserve exact
   previous CI behaviour. New-style invocations do not clean.
3. **`rsync` joins the host tool list.** `stage-source` needs it, so the
   Semaphore prologues install it alongside `devscripts`, `patchelf` and `jq`.
   That is the only CI change in the first PR.
4. **Split the Semaphore job** once the targets are proven: `make clean build`,
   then `make test`, then `make publish`, as three commands in the existing job,
   so a publish failure can be retried without a rebuild.
5. **Retire `SECRET_KEY` after CI moves.** Both paths are supported from day
   one; Semaphore's secret can move to a key id in a later change or stay a file
   indefinitely — a file path is genuinely the right shape for CI.

Two changes to the build images come with the refactor, because
`build-binaries` is the first thing to build a binary package here:

- `install-ubuntu-build-deps` gains `libelf-dev` (a Felix `Build-Depends` that
  was missing), plus `fakeroot` and `equivs`, which `dpkg-buildpackage -b` and the
  `mk-build-deps` fallback need.
- `docker-bake.hcl` moves up to `release/packaging/`, so that the build context is
  the whole packaging directory rather than just `docker-build-images/`. (buildx
  refuses a context outside the bake file's own directory without an explicit
  entitlement flag, so moving the file is the portable way to widen it.) A
  `.dockerignore` keeps `output/` and the makefiles out of it.

### The EL 7 to EL 8 move

The RPM target was CentOS 7 until AlmaLinux 8 replaced it. `EL_VERSIONS := 8`,
the image is `calico-build/el8`, and the artifacts land in
`output/dist/rpms-el8/`. What that took beyond the image itself:

- **Spec conditionals are gone.** `%if 0%{?el7}` selected the systemd scriptlets,
  and that macro is not defined on EL 8 — the packages would have silently
  reverted to their SysV init paths. Since EL 8 is now the floor, the branches are
  deleted rather than re-spelled: the specs install a systemd unit and call
  `systemctl`, unconditionally. `felix/rpm/calico-felix.init`, the EL 6 SysV
  script, goes with them, as do the `python_sitelib` fallbacks that used Python 2
  syntax.
- **The felix binary** had to be built somewhere with EL 8's glibc, which is what
  section 4.1 is about. Since the el8 image is that place, it grew a Go toolchain
  and the cgo build dependencies.
- **No vault fixup.** `utils/centos7-vault-fixup` is gone: it existed only
  because CentOS 7 is EOL and its mirror list no longer resolves. AlmaLinux 8 has
  live repositories.
- **dnsmasq and etcd3gw are removed**, for the reasons in section 4.
  `release/packaging/etcd3gw/` and the clone machinery that only dnsmasq used go
  with them.
- **EPEL is no longer enabled** in the build image. It was there for
  `python2-pbr`, which only etcd3gw needed.
- **`VERSION=vX.Y.Z-python2` is no longer accepted.** It named a Python 2 variant
  of the PPA and RPM repo, from the era when we published Python 2 packages, and
  now fails the version check like any other unrecognised value.

### Risk register

| Change | Risk | Mitigation |
|---|---|---|
| Staging copies replace in-tree builds | A component's `debian/rules` or spec assumes it is in a git checkout | `stage-source` uses `rsync -a` including `.git` by default; the per-component excludes opt out |
| Dropping the RPM-before-deb ordering | Felix deb built against an unpatched binary | The patchelf moves into the deb staging step, so it is now impossible to skip |
| One excludes list per component | The merged list differs from either original | The tarball file lists were compared for all three components; `build-binaries` and `test` now fail if a package is missing something it installs |
| Incremental output dir | A stale artifact from an earlier version gets published | The version is in every filename; `make clean` in CI; publish targets are keyed to the current `$(DEB_VERSION)` |
| New `test` step | A stock EL image may lack repositories for some packages' Requires | `RPM_TEST_PACKAGES` names what to install, and `test` is optional and not on the publish path |

## 10. What the first run found

The deliverable was package contents equivalent to the old pipeline's, not just a
pipeline that runs, so the phases were exercised end to end before merging:
source packages for all three components on all three series, binary `.debs`,
RPMs for EL 8, install verification, and
`publish-ubuntu` against the live PPA index (which skipped, correctly, because the
PPA already had that version).

Three things fell out of that, and are worth knowing about:

1. **`dpkg-source`'s `-I` is not what it looks like.** A bare `-I` *adds* the
   default ignore list rather than clearing it, so the first version of
   `build-ubuntu` produced a Felix source package with no BPF objects in it — and
   `build-binaries` failed on it immediately, which is the entire argument for
   that phase existing.
2. **`calico-felix` does not run on Ubuntu 20.04, and cannot be installed on EL
   7.** The binary we ship needs `GLIBC_2.34`; Focal has 2.31 and EL 7 has 2.17.
   `test-ubuntu-focal` catches it as an `ldd` failure and `test-rhel` as an
   unsatisfiable `Requires:`. This is not a packaging bug: the floor is set by
   `calico/go-build`, which is UBI 8 (glibc 2.28) on the release branches and
   AlmaLinux 9 (2.34) on master, and the master nightly RPM published from the
   same commit by the old pipeline has an identical requirement set. Nothing was
   looking for it before. See README.md.
3. **The etcd3gw RPM used to land in the wrong place.** The old container mount
   put its output in `release/packaging/release/packaging/output/`, which nothing
   ever collected. It was rarely built, so nobody noticed — and it is not built at
   all now.
