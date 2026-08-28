---
name: operator-api-standards
description: Standards, conventions, and dos/don'ts for adding or changing CRD types in the tigera/operator API (api/v1). Use this skill whenever editing or creating files under api/v1/ (any *_types.go), adding/removing/renaming a CRD field, introducing a new Kind/CRD, adding kubebuilder validation or defaulting markers, or designing an overrides/configuration field. Trigger even if the user doesn't mention "standards" — any change to operator CRD types should follow these conventions.
---

# Operator API Standards

When adding or changing CRD types under `api/v1/`:

1. **Read [`docs/api_design.md`](../../../docs/api_design.md)** — the API design
   principles plus the concrete Go/kubebuilder coding conventions (optional vs
   required fields, the `Enabled`/`Disabled` enum idiom, validation/CEL markers,
   the top-level Kind marker block, shared-type reuse, the Deployment override
   pattern) and the end-of-file **checklist**. Apply all of it, and run the
   checklist before you finish.
2. **Read [`docs/principles.md`](../../../docs/principles.md)** for related rules
   ("Respect User Input", "Resource Ownership") when a judgement call isn't
   settled by `api_design.md`.
3. Follow the post-change workflow in
   [`docs/dev_guidelines.md`](../../../docs/dev_guidelines.md) — `make gen-files`,
   verify scope didn't flip to `Namespaced`, update `convert` if relevant, and
   `make dirty-check`.
