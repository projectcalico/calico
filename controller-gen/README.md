# calico-controller-gen

A thin wrapper around [`sigs.k8s.io/controller-tools`](https://github.com/kubernetes-sigs/controller-tools)
that adds Calico-specific CRD generation behavior. Replaces the old `controller-gen`
binary patch shipped in `projectcalico/toolchain`'s `calico-go-build` image.

## What it adds

### `+calico:numOrString` marker

Place on a Go type declaration (or field) to make controller-gen emit an
int-or-string union schema:

```yaml
x-kubernetes-int-or-string: true
anyOf:
  - type: integer
  - type: string
pattern: "^.*"
```

Use it for any new struct that serializes as a number or a string (its
`MarshalJSON` / `UnmarshalJSON` does the demuxing). Equivalent in spirit to
apimachinery's `intstr.IntOrString`, which controller-tools handles out of the
box.

```go
// +calico:numOrString
type MyPort struct { ... }

// or, on a field:
type MySpec struct {
    Port MyPort `json:"port" +calico:numOrString`
}
```

### `+calico:nullableItems` marker

Place on a slice field whose elements are pointers (e.g. `[]*int`) to make
items nullable:

```yaml
items:
  type: integer
  nullable: true
type: array
```

Upstream controller-tools doesn't auto-detect that `[]*T` elements should be
nullable. Its `kubebuilder:validation:items:` prefix only covers
ValidationMarkers (`Nullable` lives in FieldOnlyMarkers), so we ship our own.

```go
type IPAMBlockSpec struct {
    // +calico:nullableItems
    Allocations []*int `json:"allocations"`
}
```

The marker errors at generation time if applied to a non-array field, so
misuse fails loudly instead of producing a silently-broken CRD.

## CLI

Identical to upstream `controller-gen`:

```sh
calico-controller-gen crd:allowDangerousTypes=true,crdVersions=v1 \
    paths=./pkg/apis/... output:crd:dir=config/crd/

# List all available markers (including +calico:numOrString)
calico-controller-gen crd -www
```

## Using from a Calico sub-Makefile

`lib.Makefile` exposes two helpers — see its `Calico-extended controller-gen`
section. The most common form is:

```make
$(call gen-calico-crds,./pkg/apis/...,config/crd/)
```

For non-default args, build the invocation directly:

```make
$(DOCKER_GO_BUILD) sh -c '$(CALICO_CONTROLLER_GEN) \
    crd:allowDangerousTypes=true,crdVersions=v1 \
    paths=./pkg/apis/... \
    output:crd:dir=config/crd/'
```

## Layout

```
controller-gen/
├── cmd/calico-controller-gen/   # CLI entry point (mirrors upstream main.go)
├── pkg/calico/                  # marker + KnownPackages overrides
├── go.mod                       # separate module – tool deps stay isolated
└── README.md
```

## Testing

```sh
cd controller-gen
go test ./...
```

The unit tests cover the marker semantics and the package-override
registration. Schema-level parity with the patched upstream binary is
verified by regenerating any existing CRD (e.g. `api/config/crd/`) and
diffing — the only differences should be from the `prettier` post-processing
step in the API Makefile.
