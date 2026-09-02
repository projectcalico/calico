# Development Principles

Code architecture and design principles for the operator. For developer workflow, tooling, and day-to-day procedures, see [dev_guidelines.md](dev_guidelines.md).

## API Design

API design principles and the Go/kubebuilder coding conventions for `api/v1` CRD types have their own guide: see [api_design.md](api_design.md).

## Respect User Input

- **Never overwrite user-specified fields.** If a user sets a value on a resource, the operator must not silently replace it with a default or computed value.
- **Never delete user-created resources.** Secrets, ConfigMaps, and other resources created by the user are theirs. The operator should not remove them.
- **`operator.tigera.io` resources are user input too.** The operator must not delete its own CRs, not even the ones its controllers act on. If a resource can't be supported (a Goldmane CR on an Enterprise installation, say), set degraded with a message naming the resource and let the user delete it.
- **Error on inconsistent input, don't guess.** If a user provides configuration that is contradictory or ambiguous, surface a clear error rather than assuming intent. Guessing leads to subtle, hard-to-debug behavior.
- **Track field ownership on shared resources.** Where possible, write fields to APIs like FelixConfiguration, BGPConfiguration, etc. Use an annotation to track which fields the operator originally set. Never update or remove a field that wasn't set by the operator — that would overwrite user intent. If fields on these objects conflict with `operator.tigera.io` API configuration, surface an error.
- **Copy user-provided resources downstream, never modify them.** Users provide input (custom certs, ConfigMaps, pull secrets, etc.) in the `tigera-operator` namespace. The operator copies and reconciles those objects into the downstream namespaces that need them, but must never edit, update, or delete the originals.

## Component Isolation

- **New components default to `calico-system`.** Historically, each component got its own namespace for RBAC, NetworkPolicy, and resource cleanup isolation. In practice this increases cluster footprint significantly. Modern practice is to place new components in `calico-system` and only use a separate namespace when circumstances specifically call for it (e.g., strict multi-tenant isolation requirements).
- **One CRD per component.** Each component has its own CRD, controller, and status manager. Controllers interact through the Kubernetes API, not by calling each other directly.

## Controller Design

- **Watch, reconcile, render, apply.** Controllers follow a consistent pattern:
  1. Watch the primary CRD and dependent resources.
  2. Read current state from the Kubernetes API.
  3. Call into `pkg/render` to generate desired resources.
  4. Apply via `CreateOrUpdateOrDelete`.
  5. Report status via the TigeraStatus API.
- **Render packages are pure.** The `pkg/render` package generates Kubernetes manifests from inputs. It should not make API calls or have side effects — that's the controller's job.
- **Status messages are for users, not developers.** TigeraStatus conditions should be actionable and user-facing. Don't surface internal error strings or stack traces.

## Variants

- **Core code is variant-blind.** Controllers and render packages outside `pkg/enterprise` must not name a variant, in code or in comments. Behavior a single variant needs registers through `pkg/extensions`.
- **A controller only one variant runs lives in `pkg/enterprise/controller`, and its render code in `pkg/enterprise/render`.** Both mirror the core tree they came from. The controller is contributed through the controller list on `ControllerOptions` rather than named by `AddToManager`, so it carries no variant check of its own.

## Security

- **Component-to-component communication must be authenticated and encrypted.** Use mTLS or TLS + token-based authentication for all internal communication between operator-managed components.

## Resource Ownership

- **Operator-created resources use OwnerReferences.** Objects created by the operator should have OwnerReferences so they get cleaned up automatically. Exceptions exist for resources where cascading deletion would be catastrophic (e.g., CRDs).
- **User-provided resources must NOT have OwnerReferences.** This is how the operator distinguishes user-provided from operator-managed resources. They may be copied to other namespaces (with OwnerReferences on the copies), but the originals must not be claimed.