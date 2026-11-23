# app-policy glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `app-policy/`, which builds Dikastes. The Felix side of the Policy Sync API lives in `felix/policysync/`, and the per-pod socket machinery in `pod2daemon/`.

## Building blocks

The top layer of Dikastes.

| Building block | Code | Responsible for |
|---|---|---|
| Server | `app-policy/pkg/dikastes/dikastes.go` (`RunServer`) | Runs the Envoy `ext_authz` gRPC server on a Unix domain socket and starts the policy sync client. |
| Auth server | `app-policy/checker/server.go` (`authServer`) | Hands each `CheckRequest` to the check providers enabled for it and returns the verdict. |
| ALP check provider | `app-policy/checker/alp_check_provider.go` (`ALPCheckProvider`) | Evaluates tiers, policies and profiles for the local workload endpoint. |
| Request cache | `app-policy/checker/requestcache.go` (`requestCache`) | Memoizes the per-request peer, identity and namespace lookups. |
| Policy store manager | `app-policy/policystore/store.go` (`PolicyStoreManager`) | Holds the current and pending policy stores and switches them when the policy sync client reports in-sync. |
| Policy sync client | `app-policy/syncher/syncserver.go` (`SyncClient`) | Streams policy from Felix over the Policy Sync API and reports statistics back. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Dikastes](../GLOSSARY.md#dikastes)
- [Policy Sync API](../GLOSSARY.md#policy-sync-api)
- [Subscription type](../GLOSSARY.md#subscription-type)

**Application layer policy**:
Calico policy rules that match on L7 attributes, such as HTTP method, path and the caller's service account, enforced by Dikastes. "ALP" is an accepted abbreviation in code.
Code: `app-policy/checker/alp_check_provider.go` (`ALPCheckProvider`).
_Avoid_: L7 policy, sidecar policy

**Check provider**:
A pluggable evaluator that decides whether it handles a `CheckRequest` and returns the verdict.
Code: `app-policy/checker/provider.go` (`CheckProvider`).

**Policy scope**:
Whether an evaluation ignores staged policies (`EnforcedOnly`) or treats them as enforced (`StagedAsEnforced`). The `StagedAsEnforced` result is what Goldmane records as the pending policy trace.
Code: `app-policy/checker/check.go` (`PolicyScope`).
_Avoid_: pending verdict

**Policy store**:
The in-memory copy of the policies, profiles, IP sets, endpoints, service accounts and namespaces that Felix has streamed to this Dikastes.
Code: `app-policy/policystore/store.go` (`PolicyStore`).
_Avoid_: policy cache

**Current store and pending store**:
The policy store that requests read from, and the policy store the policy sync client rebuilds after a reconnect until Felix reports in-sync. Requests keep reading the current store during the rebuild. The pending store has nothing to do with staged policy.
Code: `app-policy/policystore/store.go` (`policyStoreManager`).
_Avoid_: pending policy (that means a staged policy)

**Policy sync client**:
The Dikastes side of the Policy Sync API. It subscribes to Felix, applies each update to the pending store or current store, and sends statistics back with `Report`. Its package is named `syncher`.
Code: `app-policy/syncher/syncserver.go` (`SyncClient`).
_Avoid_: syncher, sync server

**Policy Sync server**:
The Felix side of the Policy Sync API.
Code: `felix/policysync/server.go` (`Server`).
_Avoid_: nodeagent

**In-sync**:
The point at which Felix has sent the whole initial policy snapshot to the policy sync client. The pending store becomes the current store at that point.
Code: `app-policy/policystore/store.go` (`OnInSync`).
_Avoid_: ready, synced
