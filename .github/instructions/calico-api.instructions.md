---
applyTo:
  - "api/pkg/apis/projectcalico/v3/**"
  - "libcalico-go/lib/apis/internalapi/**"
  - "libcalico-go/lib/validator/v3/**"
  - "webhooks/pkg/**"
---

# Calico API validation

A `projectcalico.org/v3` resource reaches Calico through one of two admission paths:

- the Calico API server (or `calicoctl`/`clientv3`), which runs the Go validator in
  `libcalico-go/lib/validator/v3` (the `validate:"..."` struct tags);
- the v3 CRDs directly, where Kubernetes enforces only the CRD schema (kubebuilder markers and
  CEL). The `calico-webhooks` admission webhook adds the Go validator for the policy kinds
  only.

So a field validated only by a struct tag is unvalidated on a v3-CRD cluster unless it belongs
to a policy kind. Downstream code (the update processors, Felix's calculation graph) assumes
selectors and names are valid; an invalid value can drop a selector (widening a rule) or panic
Felix.

## Reviewing changes to API types

Flag any of the following:

- A Calico selector field (string holding Calico selector syntax) without
  `validate:"selector"` (`omitempty,selector` when optional), or, on a CRD-backed type, without
  `+kubebuilder:validation:MaxLength=1024`. The length bound also bounds the nesting depth Felix
  has to parse.
- A field holding a Kubernetes object name (service account, namespace, …) without
  `validate:"name"` (`omitempty,dive,name` for a list) and a matching CRD bound
  (`MaxLength`/`Pattern`, or `items:MaxLength`/`items:Pattern` for a list). Calico interpolates
  these names into selectors, so an unvalidated name can break selector quoting.
- Validation that exists only as a struct tag or struct validator on a non-policy resource,
  with no CRD-schema or CEL equivalent.
- Code that builds a selector by string formatting from a value that this validation does not
  constrain.
- A new policy kind not added to the webhook's validation in `webhooks/pkg/rbac`.
