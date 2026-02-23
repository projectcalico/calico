---
name: implement-calico-api-resource
description: Implements a new Calico API resource by plumbing it through all layers of the codebase. Use after API design is complete (see design-kubernetes-api skill).
---

## Prerequisites

Before using this skill, ensure you have:
- A designed API resource (Go structs with kubebuilder annotations, json tags, etc.) — use the `design-kubernetes-api` skill first.
- Know whether the resource is **namespaced** or **cluster-scoped**.
- Know the **Kind**, **plural name**, and any **short names** for kubectl.

## Overview of Layers

Adding a new Calico API resource touches these layers (in dependency order):

1. **API type definition** (`api/pkg/apis/projectcalico/v3/`)
2. **Code generation** (deepcopy, clients, informers, listers, OpenAPI)
3. **CRD operator types** (`libcalico-go/lib/apis/crd.projectcalico.org/v1/`)
4. **CRD v1 scheme registration** (`libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme/scheme.go`)
5. **Backend model registration** (`libcalico-go/lib/backend/model/resource.go`)
6. **K8s backend resource client** (`libcalico-go/lib/backend/k8s/resources/`)
7. **K8s backend client registration** (`libcalico-go/lib/backend/k8s/client.go`)
8. **Namespace helper** (if namespaced) (`libcalico-go/lib/namespace/resource.go`)
9. **Validator** (`libcalico-go/lib/validator/v3/validator.go`)
10. **clientv3 typed client** (`libcalico-go/lib/clientv3/`)
11. **Apiserver registry** (storage, strategy, REST) (`apiserver/pkg/registry/projectcalico/`)
12. **Apiserver Calico storage adapter** (`apiserver/pkg/storage/calico/`)
13. **Apiserver storage interface switch** (`apiserver/pkg/storage/calico/storage_interface.go`)
14. **Apiserver converter** (`apiserver/pkg/storage/calico/converter.go`)
15. **Apiserver REST storage provider** (`apiserver/pkg/registry/projectcalico/rest/storage_calico.go`)
16. **Felix syncer** (if Felix needs this resource) (`libcalico-go/lib/backend/syncersv1/felixsyncer/`)
17. **RBAC** (Helm chart RBAC for node/operator)
18. **Manifests and CRD YAML** (generated)

## Workflow

Work through the following steps in order. Each step references specific files and patterns to follow.

### Step 1: API Type Definition

Create the Go type file in `api/pkg/apis/projectcalico/v3/`.

**File:** `api/pkg/apis/projectcalico/v3/<resourcename>.go`

Follow this pattern (using BGPFilter as a clean example):

```go
// Copyright (c) <YEAR> Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 ...

package v3

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

const (
    KindMyResource     = "MyResource"
    KindMyResourceList = "MyResourceList"
)

// +genclient:nonNamespaced  (cluster-scoped only)
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MyResourceList contains a list of MyResource resources.
type MyResourceList struct {
    metav1.TypeMeta `json:",inline"`
    metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
    Items []MyResource `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// For cluster-scoped:
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster,shortName={myres}

// For namespaced:
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Namespaced,shortName={myres}

// MyResource represents <description suitable for CRD schema docs>.
type MyResource struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
    Spec MyResourceSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}

// MyResourceSpec contains the specification for a MyResource resource.
type MyResourceSpec struct {
    // ... fields with kubebuilder validation annotations
}

// NewMyResource creates a new (zeroed) MyResource struct with TypeMetadata initialised.
func NewMyResource() *MyResource {
    return &MyResource{
        TypeMeta: metav1.TypeMeta{
            Kind:       KindMyResource,
            APIVersion: GroupVersionCurrent,
        },
    }
}
```

**Key annotations:**
- `+genclient` — generates typed client code
- `+genclient:nonNamespaced` — for cluster-scoped resources (put on BOTH the list type and the main type)
- `+k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object` — generates DeepCopyObject()
- `+kubebuilder:resource:scope=Cluster|Namespaced` — CRD scope
- `+kubebuilder:resource:shortName={...}` — kubectl short names

**Gotcha:** The `List` type needs `+genclient:nonNamespaced` too (for cluster-scoped resources), and `+k8s:deepcopy-gen:interfaces=...` on both types. Do NOT put `+kubebuilder:resource` on the List type — only on the main resource type.

### Step 2: Register in API Scheme

**File:** `api/pkg/apis/projectcalico/v3/register.go`

Add both types to the `AllKnownTypes` slice:

```go
AllKnownTypes = []runtime.Object{
    // ... existing types ...
    &MyResource{},
    &MyResourceList{},
}
```

### Step 3: Run API Code Generation

```bash
cd api && make gen-files
```

This generates the DeepCopy methods, typed Kubernetes client, informers, listers, and OpenAPI schema needed for compilation of downstream layers:
- `api/pkg/apis/projectcalico/v3/zz_generated.deepcopy.go` — DeepCopy methods
- `api/pkg/client/clientset_generated/` — typed Kubernetes client
- `api/pkg/client/informers_generated/` — informer factories
- `api/pkg/client/listers_generated/` — listers
- `api/pkg/openapi/generated.openapi.go` — OpenAPI schema

Run this early so the remaining steps can compile against the generated types. A full `make generate` at the project root is still needed later (Step 19) to pick up CRDs, manifests, and other downstream generated files.

### Step 4: CRD Operator Types (crd.projectcalico.org/v1)

Calico has a dual-CRD system. Older clusters use `crd.projectcalico.org/v1` CRDs, newer ones use `projectcalico.org/v3`. New resources need a type definition in the v1 scheme for backward compatibility.

**File:** `libcalico-go/lib/apis/crd.projectcalico.org/v1/<myresource>_types.go`

```go
package v1

import (
    v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster  // or Namespaced
type MyResource struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    Spec              v3.MyResourceSpec `json:"spec,omitempty"`
}
```

Note: the v1 type re-uses the v3 Spec struct — only the top-level wrapper differs.

### Step 5: Register in CRD v1 Scheme

**File:** `libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme/scheme.go`

Add the type to the `BuilderCRDv1()` function's `AddKnownTypes` call:

```go
&apiv3.MyResource{},
&apiv3.MyResourceList{},
```

### Step 6: Backend Model Registration

**File:** `libcalico-go/lib/backend/model/resource.go`

Add to the `init()` function:

```go
registerResourceInfo[apiv3.MyResource](apiv3.KindMyResource, "myresources")
```

The plural name here must match the CRD plural. This enables the generic `ResourceKey`-based storage path.

### Step 7: K8s Backend Resource Client

**File:** `libcalico-go/lib/backend/k8s/resources/<myresource>.go`

For simple resources that use the v3 CRDs directly (typical for new resources):

```go
package resources

import (
    "reflect"

    apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
    "k8s.io/client-go/rest"
)

const (
    MyResourceResourceName = "MyResources"
)

func NewMyResourceClient(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
    return &customResourceClient{
        restClient:      r,
        resource:        MyResourceResourceName,
        k8sResourceType: reflect.TypeOf(apiv3.MyResource{}),
        k8sListType:     reflect.TypeOf(apiv3.MyResourceList{}),
        kind:            apiv3.KindMyResource,
        apiGroup:        group,
    }
}
```

**Gotcha:** The `resource` field is the CRD resource name (plural, PascalCase used by the REST client).

### Step 8: Register in K8s Backend Client

**File:** `libcalico-go/lib/backend/k8s/client.go`

Add to the resource client registration block:

```go
c.registerResourceClient(
    reflect.TypeOf(model.ResourceKey{}),
    reflect.TypeOf(model.ResourceListOptions{}),
    apiv3.KindMyResource,
    resources.NewMyResourceClient(restClient, group),
)
```

If there is any CRD cleanup or garbage-collection mechanism for v3 kinds in this client, ensure your new kind is included there as appropriate.

### Step 9: Namespace Helper (if namespaced)

**File:** `libcalico-go/lib/namespace/resource.go`

If your resource is namespaced, add its Kind to the `IsNamespaced` switch:

```go
func IsNamespaced(kind string) bool {
    switch kind {
    case // ... existing cases ...,
        apiv3.KindMyResource:
        return true
    // ...
    }
}
```

### Step 10: Validator

**File:** `libcalico-go/lib/validator/v3/validator.go`

**Prefer kubebuilder annotations** for validation wherever possible (e.g., `+kubebuilder:validation:Enum`, `+kubebuilder:validation:Pattern`, `+kubebuilder:validation:Required`). Kubebuilder annotations generate CRD schema validation that is enforced by the Kubernetes API server. The Go struct validator in this file is only executed by the `crd.projectcalico.org/v1` code path — it is **not** executed for `projectcalico.org/v3` CRDs, so any validation that only lives here will be silently skipped on newer clusters.

If your resource needs cross-field or complex validation that cannot be expressed with kubebuilder annotations, register a struct validator:

```go
// In the init/registration function:
registerStructValidator(validate, validateMyResourceSpec, api.MyResourceSpec{})

// Validation function:
func validateMyResourceSpec(structLevel validator.StructLevel) {
    spec := structLevel.Current().Interface().(api.MyResourceSpec)
    // ... validation logic ...
}
```

Simple resources may not need custom validation if kubebuilder annotations are sufficient.

### Step 11: clientv3 Typed Client

**File:** `libcalico-go/lib/clientv3/<myresource>.go`

Create the typed client interface and implementation:

```go
package clientv3

import (
    "context"
    v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
    "github.com/projectcalico/calico/libcalico-go/lib/options"
    validator "github.com/projectcalico/calico/libcalico-go/lib/validator/v3"
    "github.com/projectcalico/calico/libcalico-go/lib/watch"
)

// MyResourceInterface has methods to work with MyResource resources.
type MyResourceInterface interface {
    Create(ctx context.Context, res *v3.MyResource, opts options.SetOptions) (*v3.MyResource, error)
    Update(ctx context.Context, res *v3.MyResource, opts options.SetOptions) (*v3.MyResource, error)
    Delete(ctx context.Context, name string, opts options.DeleteOptions) (*v3.MyResource, error)
    Get(ctx context.Context, name string, opts options.GetOptions) (*v3.MyResource, error)
    List(ctx context.Context, opts options.ListOptions) (*v3.MyResourceList, error)
    Watch(ctx context.Context, opts options.ListOptions) (watch.Interface, error)
}

// myResources implements MyResourceInterface
type myResources struct {
    client client
}

func (r myResources) Create(ctx context.Context, res *v3.MyResource, opts options.SetOptions) (*v3.MyResource, error) {
    if err := validator.Validate(res); err != nil {
        return nil, err
    }
    out, err := r.client.resources.Create(ctx, opts, v3.KindMyResource, res)
    if out != nil {
        return out.(*v3.MyResource), err
    }
    return nil, err
}

// ... Update, Delete, Get, List, Watch follow the same pattern.
// For namespaced: Delete/Get take (namespace, name) instead of just name.
// For namespaced: use namespace parameter instead of noNamespace constant.
```

**File:** `libcalico-go/lib/clientv3/interface.go`

Add the client interface:

```go
type MyResourceClient interface {
    MyResources() MyResourceInterface
}
```

Add `MyResourceClient` to the main `Interface` interface.

**File:** `libcalico-go/lib/clientv3/client.go`

Add the accessor method:

```go
func (c client) MyResources() MyResourceInterface {
    return myResources{client: c}
}
```

### Step 12: Apiserver Registry

Create a new directory: `apiserver/pkg/registry/projectcalico/<myresource>/`

**File:** `apiserver/pkg/registry/projectcalico/<myresource>/storage.go`

Follow the pattern from `apiserver/pkg/registry/projectcalico/ipamconfig/storage.go`:
- `EmptyObject()` returns `&calico.MyResource{}`
- `NewList()` returns `&calico.MyResourceList{}`
- `NewREST()` creates the registry.Store with:
  - `KeyRootFunc` / `KeyFunc` using `opts.KeyRootFunc(namespaced)` / `opts.KeyFunc(namespaced)`
  - `NoNamespaceKeyFunc` (cluster-scoped) or `NamespaceKeyFunc` (namespaced)
  - `DefaultQualifiedResource: calico.Resource("myresources")`

**File:** `apiserver/pkg/registry/projectcalico/<myresource>/strategy.go`

Follow the pattern from `apiserver/pkg/registry/projectcalico/ipamconfig/strategy.go`:
- `NamespaceScoped()` returns true/false based on resource scope
- `GetAttrs`, `MatchMyResource`, `MyResourceToSelectableFields` functions

### Step 13: Apiserver Calico Storage Adapter

**File:** `apiserver/pkg/storage/calico/<myresource>_storage.go`

Follow the pattern from `apiserver/pkg/storage/calico/ipamconfig_storage.go`. This wires the apiserver to the libcalico-go clientv3:

```go
func NewMyResourceStorage(opts Options) (registry.DryRunnableStorage, factory.DestroyFunc) {
    c := CreateClientFromConfig()
    createFn := func(ctx context.Context, c clientv3.Interface, obj resourceObject, opts clientOpts) (resourceObject, error) {
        oso := opts.(options.SetOptions)
        res := obj.(*api.MyResource)
        return c.MyResources().Create(ctx, res, oso)
    }
    // ... update, get, delete, list, watch functions ...
    // Build resourceStore with converter
}
```

Include a converter struct that handles `convertToLibcalico`, `convertToAAPI`, and `convertToAAPIList`. For simple resources where the API type is the same in both layers, the converter is a straightforward field copy.

### Step 14: Apiserver Storage Interface Switch

**File:** `apiserver/pkg/storage/calico/storage_interface.go`

Add a case to the `NewStorage` switch:

```go
case "projectcalico.org/myresources":
    return NewMyResourceStorage(opts)
```

### Step 15: Apiserver Converter

**File:** `apiserver/pkg/storage/calico/converter.go`

Add a case to the `convertToAAPI` function:

```go
case *v3.MyResource:
    aapi := &v3.MyResource{}
    MyResourceConverter{}.convertToAAPI(obj, aapi)
    return aapi
```

### Step 16: Apiserver REST Storage Provider

**File:** `apiserver/pkg/registry/projectcalico/rest/storage_calico.go`

1. Add import for the new registry package
2. Create REST options and server.Options (follow the existing pattern)
3. Add to the storage map:

```go
storage["myresources"] = rESTInPeace(calico<myresource>.NewREST(scheme, *myresourceOpts))
```

### Step 17: Syncers (Conditional)

**Only needed if a component (Felix, confd, etc.) needs to watch this resource.**

New resources use `ResourceKey` and are passed directly through the syncer layer without transformation. This means you typically do NOT need an update processor.

**File:** `libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go`

Add to the appropriate section (always-on or leader-only):

```go
{
    ListInterface: model.ResourceListOptions{Kind: apiv3.KindMyResource},
},
```

No `UpdateProcessor` is needed for resources using `ResourceKey` — they pass through as-is to Felix/confd.

**Alternative: Components using Kubernetes informers** — Some components (kube-controllers, webhooks) use the generated Kubernetes informers from `api/pkg/client/informers_generated/` instead of the syncer layer. These components automatically pick up new resources after code generation (Step 3) without additional plumbing. Check if your consuming component uses:
- **Syncer** (Felix, Typha via syncer): needs explicit registration in the syncer.
- **Informers** (kube-controllers, etc.): automatically available after codegen, but may need wiring in the controller.

### Step 18: calicoctl Resource Manager

**File:** `calicoctl/calicoctl/resourcemgr/<myresource>.go`

Register the resource for calicoctl CRUD commands (create, get, update, delete, replace). This is a single file with an `init()` function — no other calicoctl files need changing.

```go
package resourcemgr

import (
	"context"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewMyResource(),
		newMyResourceList(),
		false, // isNamespaced
		[]string{"myresource", "myresources"},
		[]string{"NAME"},
		[]string{"NAME"},
		map[string]string{
			"NAME": "{{.ObjectMeta.Name}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.MyResource)
			return client.MyResources().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.MyResource)
			return client.MyResources().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.MyResource)
			return client.MyResources().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.MyResource)
			return client.MyResources().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.MyResource)
			return client.MyResources().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

func newMyResourceList() *api.MyResourceList {
	return &api.MyResourceList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindMyResourceList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
```

For **namespaced** resources: set `isNamespaced` to `true`, add `"NAMESPACE": "{{.ObjectMeta.Namespace}}"` to the headings map, and pass `r.Namespace` as the first argument to Delete/Get/List client calls.

The `init()` function auto-registers the resource — calicoctl's generic CRUD commands, help text, and resource name resolution all pick it up automatically.

### Step 19: RBAC

**File:** `charts/calico/templates/calico-node-rbac.yaml` (and/or operator role templates)

Add RBAC rules for the new resource if components need to access it:

```yaml
- apiGroups: ["projectcalico.org"]
  resources: ["myresources"]
  verbs: ["get", "list", "watch"]
```

### Step 20: Full Generation, Formatting, and Commit

```bash
# Regenerate everything — CRDs, manifests, CI config, and any remaining generated files
make generate

# This also runs make fix-changed automatically at the end.
# Verify
make yaml-lint
make check-go-mod
```

**Gotcha:** `make generate` at the project root produces many downstream files beyond the `api/` directory — CRD YAML in `manifests/`, Helm chart outputs, Semaphore CI config, etc. You MUST commit all generated files alongside your source changes. CI will reject PRs with stale generated files.

## Checklist Summary

Use this checklist to verify completeness:

- [ ] API type file in `api/pkg/apis/projectcalico/v3/`
- [ ] Registered in `api/pkg/apis/projectcalico/v3/register.go` (`AllKnownTypes`)
- [ ] Code generation run (`cd api && make gen-files`)
- [ ] CRD v1 type in `libcalico-go/lib/apis/crd.projectcalico.org/v1/`
- [ ] CRD v1 scheme registration in `.../scheme/scheme.go`
- [ ] Backend model registered in `libcalico-go/lib/backend/model/resource.go`
- [ ] K8s backend resource client in `libcalico-go/lib/backend/k8s/resources/`
- [ ] K8s backend client registration in `libcalico-go/lib/backend/k8s/client.go`
- [ ] Namespace helper updated (if namespaced) in `libcalico-go/lib/namespace/resource.go`
- [ ] Validator in `libcalico-go/lib/validator/v3/validator.go` (if needed)
- [ ] clientv3 typed client in `libcalico-go/lib/clientv3/`
- [ ] clientv3 interface updated in `libcalico-go/lib/clientv3/interface.go`
- [ ] clientv3 client accessor in `libcalico-go/lib/clientv3/client.go`
- [ ] Apiserver registry (storage.go + strategy.go) in `apiserver/pkg/registry/projectcalico/<resource>/`
- [ ] Apiserver Calico storage adapter in `apiserver/pkg/storage/calico/<resource>_storage.go`
- [ ] Apiserver storage interface switch in `apiserver/pkg/storage/calico/storage_interface.go`
- [ ] Apiserver converter case in `apiserver/pkg/storage/calico/converter.go`
- [ ] Apiserver REST storage provider in `apiserver/pkg/registry/projectcalico/rest/storage_calico.go`
- [ ] Felix syncer (if needed) in `libcalico-go/lib/backend/syncersv1/felixsyncer/felixsyncerv1.go`
- [ ] calicoctl resource manager in `calicoctl/calicoctl/resourcemgr/<resource>.go`
- [ ] RBAC rules in Helm charts
- [ ] Formatting applied (`make fix-changed`)
- [ ] All generated files committed

## Common Gotchas

1. **Forgetting to regenerate:** Always run `cd api && make gen-files` after changing API types, and `make generate` at root level for CRDs and manifests.

2. **CRD plural mismatch:** The plural name must be consistent across `model/resource.go`, the apiserver storage interface, the REST storage provider, and the CRD YAML. Kubernetes lowercases everything.

3. **Missing scheme registration:** Resources must be registered in BOTH `api/pkg/apis/projectcalico/v3/register.go` (the API scheme) AND `libcalico-go/lib/apis/crd.projectcalico.org/v1/scheme/scheme.go` (the CRD v1 scheme).

4. **Dual CRD versions:** Calico supports both `crd.projectcalico.org/v1` and `projectcalico.org/v3` CRDs. New resources need type definitions and resource clients that handle both API groups, or at minimum a type in the v1 scheme.

5. **Syncer vs Informer confusion:** Felix/Typha use the syncer layer (explicit registration needed). Kube-controllers and webhooks use Kubernetes informers (automatic from codegen). Check which pattern your consuming component uses.

6. **ResourceKey passthrough:** New resources should use `ResourceKey`/`ResourceListOptions` for the syncer. They do NOT need update processors — the resource passes through as-is. Only legacy resources that need v1-to-v3 conversion use update processors.

7. **Status subresource:** If your resource has a Status field, you need additional apiserver plumbing for the `/status` subresource endpoint (see `kubecontrollersconfig` for an example).
