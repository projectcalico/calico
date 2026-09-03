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
- **ALWAYS** fetch remote files and repos with `$(call fetch_file,...)` and
  `$(call fetch_repo,...)`, not `curl` or `git clone` directly — they
  centralise the retry and throttling handling. See
  [`.github/instructions/external-downloads.instructions.md`](../.github/instructions/external-downloads.instructions.md).

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
4. A warranted edit is normally **one to three lines**, into the section that
   already covers the area — never a paraphrase of the commit message or PR
   description, and no new `###` heading for a new behaviour. Past about five
   lines you are narrating the change. A doc already past ~500 lines gets
   compressed by the next PR that touches it, not grown.
5. **In doubt, propose — don't write.** Keep the edit out of the PR: show the
   user the target file, the target section and the exact lines, and wait for
   approval. Raise it at the pre-commit checkpoint, batched into a single ask,
   so it never blocks the code work. When one of the three conditions in rule 3
   clearly holds, just make the edit.
6. Before writing or reviewing a design-doc edit, load the
   [`design-doc-edits`](skills/design-doc-edits/SKILL.md) skill — the altitude
   rule, the worked example and the reviewer criteria are there rather than
   here, so they are not in context for every session.

Rules 3-5 are mirrored for Copilot in
[`.github/copilot-instructions.md` → Documentation map](../.github/copilot-instructions.md)
— keep the two in sync. Copilot has no skills, so rule 6's content is a file it
reads rather than a skill it loads.

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

## AI-assisted contribution policy

[`AI_POLICY.md`](../AI_POLICY.md) at the repo root governs contributions written with AI assistance. The parts that affect what you produce:

- The PR description discloses the assistance - the PR template has an **AI assistance** line for it.
- Never add an AI co-author or `Assisted-By:` trailer to a commit.
- The human author has to be able to explain the change without you, so leave the code and the PR description in a state they can defend.
- Don't reply to review comments on their behalf.

## Additional Resources

- **Developer Guide:** `DEVELOPER_GUIDE.md`
- **Contributing Guide:** `CONTRIBUTING.md`
- **User Documentation:** https://docs.tigera.io/calico/latest/about
- **Docs repo:** https://github.com/tigera/docs/
- **Hack docs:** `hack/docs/`
