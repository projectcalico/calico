---
name: design-doc-edits
description: Write or review an edit to a DESIGN.md — the altitude to write at, a worked example of an edit that was 34 lines too long, and the criteria for reviewing a design-doc diff. Use when about to add or change prose in any DESIGN.md or design/ sub-design, when reviewing a design-doc diff, or when compressing a design doc that has grown too large.
---

# Editing a design doc

Whether an edit is warranted at all, and the size budget for one, are in
[`.claude/CLAUDE.md` → Documentation map](../../CLAUDE.md): the default is no
edit; a warranted one is one to three lines in the same PR as the code. This
skill is the rest — how to write those lines, and how to review someone else's.

## Who you are writing for

Someone who has never seen your diff and has to make the *next* change safely.
The doc records what the code promises: the mental model, the invariants, the
concepts and where their boundaries are.

The story of *your* change — the bug, the old behaviour, why it broke, what you
tried — belongs in the commit message and the PR description, which is where git
already keeps it. **Never copy or paraphrase either into a design doc.** Same
rule the repo applies to code comments: write for a reader with no diff in front
of them.

## Altitude

Write what stays true after a rename or a refactor.

- State the invariant, not the mechanism that currently enforces it.
- Name identifiers, functions and files as **one orientation pointer per
  concept**, not as a description of the plumbing.
- If a sentence would need editing when somebody renames a variable, it is too
  low.

## Worked example

A change taught Felix's BPF service syncer to keep the `default/kubernetes`
backend rather than let it drop to zero. It added 34 lines to
[`felix/design/bpf-services.md`](../../../felix/design/bpf-services.md) under a
new `### API server service: never drop to zero backends` heading, re-telling
the commit message ("This creates a hazard the generic kube-proxy model doesn't
have…", "The deadlock is therefore unique to bootstrap mode") and naming three
internal identifiers.

The durable content was one bullet, in the invariant list that was already
there:

> - The `default/kubernetes` service keeps its last-known-good backend instead
>   of dropping to zero: under `bpfNetworkBootstrap` Felix reaches the API
>   server through this NAT entry, so an empty backend list is self-severing.
>   Its backend is the control-plane host IP, stable across such an outage, so
>   retaining it is safe. Every other service still drops to zero.

A new invariant, stated in one sentence, in the section that already covered the
area, at an altitude that survives a rename.

## Reviewing a design-doc diff

- Reject prose that reads like the commit message or the PR description.
- Reject a new heading added for a single fix, and additions where a sentence
  already in the doc covers the area.
- Check the altitude: a paragraph that walks through identifiers is describing
  the plumbing, and the code already does that.
- A missing doc update that the author explicitly considered and skipped is
  **not** a blocker on its own.

## Compressing an oversized doc

A file past ~500 lines should be compressed by the next PR that touches it,
rather than grown. Compress by category, not by feel:

- change narration — the bug, the incident, "this used to", "was measured";
- claims made twice, usually once in prose and once in a review note;
- plumbing enumeration the code already states;
- editorial framing addressed at a reviewer ("worth flagging for readers").

Keep every invariant, review note and data-model statement. If a cut removes a
rule rather than the story around it, it is the wrong cut.

## Not covered here

User-facing install and upgrade instructions — the chart READMEs — are **not**
design docs; see
[`helm-charts.instructions.md`](../../../.github/instructions/helm-charts.instructions.md).
They must track every documented step, and there the safe default is the
opposite one: update.
