# Copilot instructions: tigera/operator

Kubernetes operator (operator-sdk / controller-runtime) that manages the
lifecycle of Calico and Calico Enterprise installations. Each component has its
own CRD (`api/v1`), controller (`pkg/controller/<component>`), and rendering code
(`pkg/render`).

## Where the standards live

- **API design / CRD types in `api/v1`:** [`docs/api_design.md`](../docs/api_design.md)
- **Architecture & design rationale:** [`docs/principles.md`](../docs/principles.md)
- **Developer workflow, code generation, cherry-picks:** [`docs/dev_guidelines.md`](../docs/dev_guidelines.md)
- **Running, testing, debugging:** [`docs/common_tasks.md`](../docs/common_tasks.md)

## Reviewing changes to `api/v1` CRD types

When a pull request changes CRD types under `api/v1/` (the `*_types.go` files),
review them against [`docs/api_design.md`](../docs/api_design.md) and flag
violations of:

- Optional fields are a pointer + `omitempty` + `// +optional` + a doc comment;
  required fields omit the pointer/`omitempty` and use `// +required`.
- On/off toggles use an `Enabled`/`Disabled` enum (a named string type), not a
  `*bool`.
- Constrained values carry markers: `+kubebuilder:validation:Enum` / `Minimum` /
  `Maximum` / `Pattern`.
- Fields used in a CEL `XValidation` rule set `MaxLength` / `MaxItems`; use
  `size(self.field) == 0`, never `self.field == ''` (single quotes break
  goimports).
- Prefer kubebuilder markers/CEL over reconcile-loop logic for
  defaulting/validation.
- Reuse shared types (`Metadata`, `ProbeOverride`, `corev1`/`appsv1`) instead of
  redefining them.
- Changes are additive and backward-compatible — don't change the meaning of an
  existing field or tighten validation on one.
- Every file carries the Tigera Apache-2.0 copyright header.

See `docs/api_design.md` for the full conventions, the Deployment override
pattern, and the per-field checklist. After API/CRD changes, `make gen-files`
then `make dirty-check` must be run; generated files
(`zz_generated.deepcopy.go`, `pkg/imports/crds/`, `pkg/components/`) are not
hand-edited.
