# CLAUDE.md

This file is **operational guidance** for agents working in this repo: build commands, test invocation, debugging, conventions, and the process rules every PR follows. For **architecture, invariants, and review criteria**, see [`DESIGN.md`](../DESIGN.md) at the repo root, and the per-component `DESIGN.md` files it links to. Do not look here for architecture; look there.

## Gotchas

- **NEVER** run `make ci` or `make cd` — in any component or at the root.
  Destructive CI-only targets.
- **NEVER** run `make test` at root — takes hours. Always test components individually.
- **NEVER** include customer names in code comments, commit messages, or PR
  descriptions — this repo is public. Cite a dev ticket (`CORE-1234`, `EV-1234`)
  or a GitHub issue instead; JIRA picks those keys up and links the ticket to
  the PR. Avoid `CI-1234` keys here — they track customer escalations.
- **ALWAYS** remove `FIt`/`FDescribe` before committing. Nothing in the repo
  catches these for you — check your own diff.
- **ALWAYS** commit generated files alongside source changes.

## Essential Build Commands

Builds run in Docker via `calico/go-build`; tool and base-image versions are
pinned in `metadata.mk`. Run `make help` for the full target list.

```bash
make -C <component> build   # 2-5 minutes — the usual way to build
make image                  # ALL images — 30+ minutes
```

### Running Tests

```bash
# Per component, in Docker (rebuilds tooling)
make -C felix ut

# Faster iteration, no Docker overhead
go test ./felix/calc/...

# Components with their own go.mod must be entered first
cd api && go test ./...
cd lib/std && go test ./...
cd lib/httpmachinery && go test ./...
```

**Always run FV tests via Makefile targets** — they build the required tooling
and set up permissions. See [`felix/CLAUDE.md`](../felix/CLAUDE.md) for the
Felix FV, BPF, and nftables invocations.

### Validation and Formatting

```bash
make fix-changed    # Auto-fix formatting for changed files — prefer this
make static-checks  # golangci-lint
make yaml-lint      # ~30 seconds
```

### Code Generation

```bash
make generate        # Everything: APIs, protobuf, manifests, CI config. Runs fix-changed itself.
make gen-deps-files  # After adding imports to a component — deps.txt drives downstream CI triggers.
```

**After modifying API types** (e.g. `api/pkg/apis/projectcalico/v3/felixconfig.go`),
run `make generate` — it regenerates OpenAPI specs, CRDs, deep copy, Felix
config docs, and manifests. See also `hack/docs/adding-an-api.md`.

## Generated Files (DO NOT edit directly)

| Generated file | Edit this instead | Regenerate with |
|---|---|---|
| `.semaphore/semaphore.yml` | `.semaphore/semaphore.yml.d/` templates | `make gen-semaphore-yaml` |
| `manifests/` | `charts/` | `make gen-manifests` |
| `*.pb.go` protobuf files | `.proto` sources | `make protobuf` |

After regenerating, commit the generated files alongside your source changes.

`charts/calico` is a manifest-generation template, not a chart anyone installs
with Helm - its rendered output in `manifests/` is the only contract. See
[`.github/instructions/helm-charts.instructions.md`](../.github/instructions/helm-charts.instructions.md).

## Code Conventions

### Formatting

A repo-scoped PostToolUse hook (`.claude/settings.json`) runs
`hack/cmd/format-go-file` after every Edit/Write/MultiEdit, which fixes gofmt
and import grouping (stdlib, external, calico-internal). Don't hand-format
imports.

### Copyright Headers

All new `.go` files require:
```go
// Copyright (c) <YEAR> Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...
```

eBPF files in `felix/bpf-gpl/` require dual Apache/GPL headers with SPDX
identifiers. Nothing enforces this automatically — add the header yourself.

### File layout

- Place utility methods/functions after (but close to) the methods/functions 
  that use them, generally want the context that a function is called in to 
  appear before the detail of the function body.
- For files that contain "object" structs:
  - Small typedefs/enums/constants.
  - Main struct definition
  - Constructors
  - Methods; in some intuitive ordering
    - Expected call order works well for readability "Add" before "Remove", "Start" before "Stop"
    - Group similar methods together
  - Utility functions; can be interspersed with methods if tightly coupled with particular methods.
  - Larger secondary structs at the bottom.

## Documentation map

This repo carries an extensive corpus of architecture and review guidance.
**Consult it first, instead of reverse-engineering from the code** — it captures
invariants, design rationale, and review criteria that are hard to recover from
the source alone.

- [`DESIGN.md`](../DESIGN.md) at the repo root — cross-cutting architecture, and
  the authoritative starting point for *what the repo is*.
- `<component>/DESIGN.md` — per-component architecture, invariants, and
  per-section review notes. A coding agent writing a PR and a reviewer checking
  one read the same file and apply the same embedded review notes.
- `design/<topic>/` — designs for subsystems spanning several components (e.g.
  IPAM). Pointer stubs may sit in consumer subdirectories, but the canonical
  content lives here.
- `<component>/CLAUDE.md` — operational guidance only. Not architecture.

Complex components split their design across a directory with an "applies to"
glob per topic — Felix uses [`felix/DESIGN.md`](../felix/DESIGN.md) as an index
over [`felix/design/`](../felix/design/). A PR touching multiple globs must load
every matching sub-design.

**Rules for agents reading this repo:**

1. Before writing or reviewing code in a component, read that component's
   `DESIGN.md` (or, for Felix, the sub-designs matching the paths you touch).
2. Follow links. A design is a graph, not a single node.
3. A design doc records the design, not the change that introduced it, and
   **the default is no edit**. Edit one only when a sentence in it is now
   false, a new invariant exists that a future change could silently break, or
   a new concept exists that the doc's mental model does not name. A new
   behaviour, flag, field, config key, or bug fix is not by itself any of
   those. A warranted edit lands **in the same PR as the code**, in the doc
   covering the area — for Felix, the matching sub-design, not the index.

### Editing a design doc

A design doc is written for someone who has never seen your diff and has to
make the *next* change safely. The rules below are the canonical statement;
[`.github/copilot-instructions.md` → Documentation map](../.github/copilot-instructions.md)
mirrors them for Copilot — keep the two in sync.

- Never copy or paraphrase the commit message or PR description into a design
  doc. That narrative belongs in git, exactly as for code comments.
- **In doubt, propose — don't write.** Keep the edit out of the PR: show the
  user the target file, the target section, and the exact one to three lines
  you would add, and wait for approval. Raise it at the pre-commit checkpoint,
  batched into a single ask, so it never blocks the code work. When one of the
  three conditions clearly holds, just make the edit.
- A warranted edit is normally **one to three lines**, edited into the section
  that already covers the area. Fix the existing sentence before adding a new
  one; a new `###` heading needs a new concept, not a new behaviour. Past about
  five lines you are narrating the change.
- Write at an altitude that survives a rename: state the invariant, and name
  identifiers or files as one orientation pointer per concept.
- A file already past ~500 lines should be compressed by the next PR that
  touches it, not grown.

**Worked example.** A change that taught the BPF service syncer to keep the
`default/kubernetes` backend rather than let it drop to zero added 34 lines
under a new heading in `felix/design/bpf-services.md`, re-telling its own commit
message and naming three internal identifiers. The durable content was one
bullet in the invariant list already there: *the `default/kubernetes` service
keeps its last-known-good backend instead of dropping to zero — under
`bpfNetworkBootstrap` Felix reaches the API server through this NAT entry, so an
empty backend list is self-severing.*

**Reviewing** a design-doc diff applies the same rules: reject prose that reads
like the commit message, a heading added for a single fix, or an addition where
a sentence already in the doc covers the area. A missing update the author
explicitly considered and skipped is not a blocker on its own.

## Tests required for code changes

A PR that fixes a bug must include a test that reproduces the bug. A PR that
adds a feature must include tests that exercise it. A change without a
corresponding test is the exception, and requires explicit justification
(untestable interface boundary, infrastructure-only change).

Prefer the lowest test level that meaningfully exercises the change:

1. **Unit tests** — deterministic, fast, hermetic. Always the first choice when
   the behaviour is reachable without real infrastructure.
2. **Functional verification (FV)** — real binary against real infrastructure.
   Use when the integration *is* the thing being tested.
3. **End-to-end / Kubernetes** — reserve for behaviour that genuinely needs a
   full cluster.

Tests-only follow-ups are an anti-pattern: by the time they land, the change has
shipped untested. A reviewer who sees "I tested it manually" or "tests in a
follow-up PR" should push back.

Per-area sub-designs carry area-specific test conventions on top of this rule
(e.g. [`felix/design/bpf-tests.md`](../felix/design/bpf-tests.md)).

## PR Requirements

**ALWAYS** use the PR template (`.github/PULL_REQUEST_TEMPLATE.md`). The only mandatory section is the **Release Note** — fill it in with a one-line summary of the user-facing impact of the change. Take a broad view of "user-facing": bug fixes, new features, performance improvements, and behavioral changes all qualify. If there is genuinely no user-facing impact, write "None".

Every PR needs one docs label (`docs-pr-required`, `docs-completed`, or `docs-not-required`) and one release note label (`release-note-required` or `release-note-not-required`). Optional: `cherry-pick-candidate` (bug fix backports), `needs-operator-pr` (requires operator change).

## Additional Resources

- **Developer Guide:** `DEVELOPER_GUIDE.md`
- **Contributing Guide:** `CONTRIBUTING.md`
- **User Documentation:** https://docs.tigera.io/calico/latest/about
- **Docs repo:** https://github.com/tigera/docs/
- **Hack docs:** `hack/docs/`
