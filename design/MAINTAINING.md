<!--
Copyright (c) 2026 Tigera, Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
-->

# Maintaining the design docs

Every `DESIGN.md` in this repo — and every sub-design under
[`felix/design/`](../felix/design/), [`design/ipam/`](./ipam/) and
friends — follows the rules on this page. This is the one canonical
copy. [`.claude/CLAUDE.md`](../.claude/CLAUDE.md),
[`.github/copilot-instructions.md`](../.github/copilot-instructions.md)
and the path-scoped rules under
[`.github/instructions/`](../.github/instructions/) point here; keep
them pointing rather than restating.

## What these docs are for

A design doc is written for someone who has never seen your diff and
has to make the *next* change safely. It records what the code
promises: the mental model, the invariants, the concepts and where
their boundaries are.

The story of *your* change — the bug, the old behaviour, why it
broke, what you tried — belongs in the commit message and the PR
description, which is where git already keeps it. **Never copy or
paraphrase a commit message or PR description into a design doc.**
This is the same rule the repo already applies to code comments:
write for a reader who does not have the diff in front of them.

## When to update: the three-condition test

**The default is no change.** Edit a design doc only when one of
these holds:

1. A sentence in it is now **false**.
2. There is a **new invariant** that a future change could silently
   break.
3. There is a **new concept** — a program, a map, a state machine, a
   component boundary — that the doc's mental model does not name.

A new behaviour, flag, field, config key, case, or bug fix is not by
itself any of the three. If you cannot point at the sentence that is
now wrong, or state the new invariant in one sentence, make no
change.

The per-area rules under [`.github/instructions/`](../.github/instructions/)
list the kinds of change that *usually* meet the test in their area —
a new BPF map, a new calc-graph node, a new gRPC method. Treat those
as candidates, not as a checklist that fires on its own. The three
conditions still decide.

## In doubt: propose, don't write

If you are unsure whether a change meets one of the three
conditions, keep the edit out of the PR:

- Write the proposal in final form — target file, target section, and
  the exact one to three lines you would add.
- Show it to the user and wait for approval before committing it.
- Raise it at the pre-commit checkpoint, not mid-implementation. The
  question must not block the code work.
- Batch every doc proposal for one change into a single ask.

When a condition clearly holds, just make the edit. The proposal path
is for ambiguity, not for routine updates.

**Agents with no interactive user** — the Copilot coding agent,
automated review — default to no change, and name what they
considered and skipped in the PR description, so a reviewer can ask
for it.

## Size

A doc change that follows from a code change is normally **one to
three lines**, edited into the section that already covers the area.

- Fix or extend the sentence that is already there before adding a
  new one. These docs otherwise only ever grow, because adding is
  easier than editing.
- A new `###` heading needs a new *concept*, not a new behaviour. A
  single bug fix never earns a heading.
- Past about five lines you are narrating the change. Cut it back.
- If a file has grown past ~500 lines, the next PR that touches it
  should compress rather than add.

## Altitude

Write what stays true after a rename or a refactor.

- State the invariant, not the mechanism that currently enforces it.
- Name identifiers, functions and files as **one orientation pointer
  per concept**, not as a description of the plumbing.
- If a sentence would need editing when somebody renames a variable,
  it is too low.

## Worked example

A real PR taught Felix's BPF service syncer to keep the
`default/kubernetes` backend rather than let it drop to zero. It
added 34 lines to [`felix/design/bpf-services.md`](../felix/design/bpf-services.md)
under a new `### API server service: never drop to zero backends`
heading, re-telling the commit message ("This creates a hazard the
generic kube-proxy model doesn't have…", "The deadlock is therefore
unique to bootstrap mode") and naming three internal identifiers.

The durable content was one bullet, in the invariant list that was
already there:

> - The `default/kubernetes` service keeps its last-known-good
>   backend instead of dropping to zero: under `bpfNetworkBootstrap`
>   Felix reaches the API server through this NAT entry, so an empty
>   backend list is self-severing. Every other service still drops to
>   zero.

That is condition 2 — a new invariant — stated in one sentence, in
the section that already covered the area, at an altitude that
survives a rename.

## Reviewing a design-doc diff

Reviewers apply the same rules:

- Reject prose that reads like the commit message or the PR
  description.
- Reject a new heading added for a single fix, and additions where a
  sentence already in the doc covers the area.
- A missing doc update that the author explicitly considered and
  skipped is **not** a blocker on its own.

## Exemptions

No doc change at all for: a bug fix that restores behaviour the doc
already describes, a mechanical refactor, comment or log-message
edits, a dependency bump.

User-facing install and upgrade instructions — the chart READMEs —
are **not** design docs and are not covered here; see
[`helm-charts.instructions.md`](../.github/instructions/helm-charts.instructions.md).
Those must track every documented step, and there the safe default is
to update.
