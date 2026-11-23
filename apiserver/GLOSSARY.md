# Calico apiserver glossary

Extends the [Calico glossary](../GLOSSARY.md). Terms here apply inside `apiserver/` and `webhooks/`, which share the tier authorizer.

## Building blocks

The top layer of the Calico apiserver.

| Building block | Code | Responsible for |
|---|---|---|
| Project Calico server | `apiserver/pkg/apiserver/apiserver.go` (`ProjectCalicoServer`) | A generic Kubernetes API server with the `projectcalico.org/v3` group installed. |
| REST storage provider | `apiserver/pkg/registry/projectcalico/rest/storage_calico.go` (`NewV3Storage`) | Builds one registry REST object per v3 resource, plus the status subresources. |
| Resource store | `apiserver/pkg/storage/calico/resource.go` (`resourceStore`) | Implements the Kubernetes `storage.Interface` on the libcalico-go v3 client. |
| Tier authorizer | `apiserver/pkg/registry/projectcalico/authorizer/authorizer.go` (`TierAuthorizer`) | Checks access to a tier and to the policies in it before a tiered policy operation. |
| Calico resource lister | `apiserver/pkg/apiserver/apiserver.go` (`CalicoResourceLister`) | Syncer-backed tier cache used by tier authorization. |
| Watch manager | `apiserver/pkg/registry/projectcalico/util/watch_manager.go` (`WatchManager`) | Cancels open policy watches when a tier is added. |
| RBAC calculator | `apiserver/pkg/rbac/calculator.go` (`Calculator`) | Computes a user's permissions per resource type, verb, namespace and tier. |

The admission webhooks, a separate process.

| Building block | Code | Responsible for |
|---|---|---|
| Webhook server | `webhooks/pkg/webhook/command.go` (`serveWebhookTLS`) | TLS server that registers the admission webhooks. |
| Tiered RBAC admission webhook | `webhooks/pkg/rbac/rbac.go` (`NewTieredRBACHook`) | Applies the tier authorizer, tier existence and Calico validation to tiered policy writes. |
| ClusterInformation admission webhook | `webhooks/pkg/clusterinfo/clusterinfo.go` (`RegisterHook`) | Blocks ClusterInformation writes except from Calico's own service accounts. |

## Terms

Terms defined in the [root glossary](../GLOSSARY.md) that apply in this component:

- [Admission webhooks](../GLOSSARY.md#admission-webhooks)
- [Aggregated v3 API](../GLOSSARY.md#aggregated-v3-api)
- [Calico apiserver](../GLOSSARY.md#calico-apiserver)
- [Tier authorizer](../GLOSSARY.md#tier-authorizer)
- [Tier wildcard](../GLOSSARY.md#tier-wildcard)
- [Tier-scoped resource](../GLOSSARY.md#tier-scoped-resource)

### Serving the v3 API

**Resource store**:
The `storage.Interface` implementation that reads and writes v3 resources through the libcalico-go v3 client.
Code: `apiserver/pkg/storage/calico/resource.go` (`resourceStore`).
_Avoid_: storage backend

**Storage type**:
The kind of storage that backs the registry. Only `calico`, the resource store, is used.
Code: `apiserver/pkg/registry/projectcalico/server/options.go` (`StorageType`).
_Avoid_: backend, datastore type (that is the client's `DATASTORE_TYPE` setting)

**`Store` (dry run)**:
The registry store wrapper that handles server-side dry runs.
Code: `apiserver/pkg/registry/projectcalico/util/dryrun_store.go` (`Store`).
_Avoid_: registry store (that is the store it wraps)

**ClusterInformation read-only rule**:
Through the Calico apiserver, ClusterInformation can be read but not written.
Code: `apiserver/pkg/registry/projectcalico/clusterinformation/storage.go`.
_Avoid_: nothing known

**Protocol shield**:
The serializer wrapper that restricts negotiated media types to JSON and YAML.
Code: `apiserver/pkg/apiserver/protocolshield.go` (`protocolShieldSerializer`).
_Avoid_: nothing known

### Tier authorization

**Tier selector**:
The label requirement on `projectcalico.org/tier` that restricts a list or watch to the tiers the user may read.
Code: `apiserver/pkg/registry/projectcalico/util/rbac.go` (`EnsureTierSelector`).
_Avoid_: filter (it means several things)

**Watch manager**:
The object that tracks open policy watches so they can be canceled.
Code: `apiserver/pkg/registry/projectcalico/util/watch_manager.go` (`WatchManager`).
_Avoid_: manager (it means several things in Calico)

**Calico resource lister**:
A syncer-backed cache of tiers.
Code: `apiserver/pkg/apiserver/apiserver.go` (`CalicoResourceLister`).
_Avoid_: cache (it means several things)

**RBAC calculator**:
Computes the permissions a user holds per resource type, verb, namespace and tier.
Code: `apiserver/pkg/rbac/calculator.go` (`Calculator`).
_Avoid_: tier authorizer (that is the consumer of the calculator, not the calculator)

### Admission webhooks

**Tiered RBAC admission webhook**:
The admission webhook at `/rbac` that applies the tier authorizer, tier existence and Calico validation to tiered policy writes.
Code: `webhooks/pkg/rbac/rbac.go` (`NewTieredRBACHook`).
_Avoid_: authorizer webhook

**ClusterInformation admission webhook**:
The admission webhook at `/cluster-info` that protects ClusterInformation from writes by anything but Calico's own service accounts.
Code: `webhooks/pkg/clusterinfo/clusterinfo.go` (`RegisterHook`).
_Avoid_: ClusterInformation protection hook
