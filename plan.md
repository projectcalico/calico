# Plan: Add NodeSelector Support to FelixConfiguration

## Problem Statement

Currently FelixConfiguration supports only two scoping modes:
- **Global** (name: `default`) — applies to all nodes
- **Per-node** (name: `node.<hostname>`) — applies to exactly one node

There is no way to apply a FelixConfiguration to a *group* of nodes selected by labels (e.g. all GPU nodes, all nodes in a rack, all nodes running a specific workload type). This forces operators to either create individual per-node resources (which doesn't scale) or use the global config (which is too broad).

## Current Architecture Summary

### Data Flow

```
Datastore → [Typha] → Felix Syncer → AllUpdDispatcher → ConfigBatcher → EventSequencer → Dataplane
```

1. **FelixConfiguration** resources are watched by the syncer (or received via Typha).
2. The **FelixConfigUpdateProcessor** (`libcalico-go/lib/backend/syncersv1/updateprocessors/`) converts each v3 FelixConfiguration into individual v1-style `GlobalConfigKey`/`HostConfigKey` KV pairs (one per Spec field).
3. The **ConfigBatcher** (`felix/calc/config_batcher.go`) receives all config KVs, filters `HostConfigKey` entries to only those matching the local hostname, and batches global + host config.
4. The **EventSequencer** merges global and host config into Felix's `Config` object using `UpdateFrom()` with source priorities: `DatastoreGlobal` < `DatastorePerHost`.

### Key Current Constraint

The per-node scoping is hardcoded via resource name (`"node.<hostname>"` prefix in `configurationprocessor.go:extractNode()`). The v1 model only has two key types: `GlobalConfigKey` and `HostConfigKey`. There is no intermediate "selector-scoped" config key.

## Proposed Design

### API Change

Add a `NodeSelector` field to the **FelixConfiguration** top-level struct (NOT in FelixConfigurationSpec, since the selector is metadata about applicability, not a Felix config setting):

```go
// api/pkg/apis/projectcalico/v3/felixconfig.go

type FelixConfiguration struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`

    Spec FelixConfigurationSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}
```

**Wait — putting it in Spec vs top-level:**

Following the existing Calico patterns (BGPPeer has `NodeSelector` in its Spec, IPPool has `NodeSelector` in its Spec), the field should go in FelixConfigurationSpec for consistency. However, this creates a problem: the `configUpdateProcessor` iterates ALL Spec fields and converts them to config keys — so `NodeSelector` would be incorrectly treated as a Felix config parameter.

**Resolution:** The `configUpdateProcessor` already supports skipping fields when `createV1Key()` returns nil. However, the current implementation doesn't have a mechanism to skip specific fields. We need a solution:

**Option A**: Add a struct tag `confignamev1:"-"` to mark fields that should be skipped (NOT converted to config keys). Modify `getConfigName()` and `processAddOrModified()` to recognize this tag and skip the field. This is clean and extensible.

**Option B**: Move NodeSelector to a separate struct outside Spec. This breaks Calico convention.

**Recommended: Option A** — Add `confignamev1:"-"` skip tag.

### Naming and Scoping Rules

With selector-based configs, the naming convention changes. Currently:
- `default` = global
- `node.<hostname>` = per-node

New rules:
- `default` = global (unchanged)
- `node.<hostname>` = per-node by name (unchanged, backwards compatible)
- **Any other name** (e.g. `gpu-nodes-config`, `rack-a-config`) = selector-scoped config. The `NodeSelector` field in the Spec determines which nodes it applies to.

### Precedence / Merge Order

Config sources from lowest to highest priority:
1. **Default** (built-in defaults)
2. **DatastoreGlobal** — from FelixConfiguration `default`
3. **DatastorePerSelector** (NEW) — from FelixConfigurations with a matching `NodeSelector`, merged in order (see below)
4. **DatastorePerHost** — from FelixConfiguration `node.<hostname>`
5. **ConfigFile**
6. **EnvironmentVariable**
7. **InternalOverride**

**When multiple selector-based configs match:** Fields set in later-evaluated configs override earlier ones. The merge order is alphabetical by resource name for determinism.

## Implementation Plan

### Step 1: API Changes (`api/`)

**File: `api/pkg/apis/projectcalico/v3/felixconfig.go`**

Add `NodeSelector` field to `FelixConfigurationSpec`:

```go
type FelixConfigurationSpec struct {
    // NodeSelector is a label selector that restricts this configuration to
    // only apply to nodes matching the given selector. When empty or omitted,
    // the behavior depends on the resource name:
    // - "default": applies to all nodes (global config)
    // - "node.<hostname>": applies to the named node (per-node config)
    // - any other name: applies to no nodes (NodeSelector is required)
    //
    // This field is only valid for FelixConfiguration resources whose name is
    // not "default" and does not start with "node.".
    // +optional
    NodeSelector string `json:"nodeSelector,omitempty" validate:"omitempty,selector" confignamev1:"-"`

    // ... existing fields ...
}
```

**File: `api/config/crd/`** — Regenerate CRDs with `make generate`.

### Step 2: Update Processor Skip Tag (`libcalico-go/`)

**File: `libcalico-go/lib/backend/syncersv1/updateprocessors/configurationprocessor.go`**

Modify the field-name-to-config-key mapping to support skip tags:
- In `NewConfigUpdateProcessor()`, when building the `names` set, skip fields with `confignamev1:"-"`.
- Modify `getConfigName()` to return `"-"` for skip-tagged fields.
- In `processAddOrModified()`, skip fields where `getConfigName()` returns `"-"`.

### Step 3: Validation (`libcalico-go/lib/validator/`)

**File: `libcalico-go/lib/validator/v3/validator.go`**

Extend `validateFelixConfigSpec` to validate:
- If resource name is `"default"`, `NodeSelector` MUST be empty.
- If resource name starts with `"node."`, `NodeSelector` MUST be empty.
- If resource name is anything else and `NodeSelector` is empty, warn (or reject if we want to be strict).

**Note:** Struct-level validation doesn't have easy access to the resource name. This validation may need to be a resource-level validator (on `FelixConfiguration`, not just `FelixConfigurationSpec`). Check existing patterns for resource-level validation.

### Step 4: ConfigBatcher Redesign (`felix/calc/`)

This is the core change. The current `ConfigBatcher` only handles two config scopes (global + per-host). It needs to handle selector-scoped configs.

**File: `felix/calc/config_batcher.go`**

Major changes:
1. **Store raw FelixConfiguration resources** (not just config key-values) for selector-scoped configs.
2. **Watch Node resource updates** to get the local node's labels.
3. **Evaluate selectors** when node labels or FelixConfiguration resources change.
4. **Merge matching configs** in alphabetical order by resource name.
5. **Emit merged config** as a new config source (between global and per-host).

New struct fields:
```go
type ConfigBatcher struct {
    hostname        string
    nodeLabels      map[string]string   // NEW: local node's labels

    datastoreInSync bool
    configDirty     bool

    globalConfig    map[string]string
    hostConfig      map[string]string
    selectorConfigs map[string]*selectorConfigEntry  // NEW: keyed by resource name

    datastoreReady  bool
    callbacks       configCallbacks
}

type selectorConfigEntry struct {
    selector     selector.Selector
    selectorStr  string
    config       map[string]string
}
```

New logic in `OnUpdate`:
- Register for `model.ResourceKey` updates (FelixConfiguration kind) to receive raw FelixConfiguration updates.

**Architectural Decision Point:** There are two approaches:

#### Approach A: Handle selectors in the ConfigUpdateProcessor layer

Modify the `configUpdateProcessor` to emit a new key type (e.g., `SelectorConfigKey{ResourceName, FieldName}`) for selector-scoped FelixConfigurations, alongside the selector string. The ConfigBatcher would collect these, evaluate selectors against node labels, and merge matching ones.

**Pros:** Fits the existing architecture (processor converts to v1 keys, ConfigBatcher consumes).
**Cons:** Requires a new model key type and the selector string needs to be passed along.

#### Approach B: Pass raw FelixConfiguration resources to the ConfigBatcher

Register the ConfigBatcher for FelixConfiguration resource updates (the raw v3 objects). The ConfigBatcher would handle selector evaluation and field extraction for selector-scoped configs itself, while still using GlobalConfigKey/HostConfigKey for default and per-node configs.

**Pros:** Cleaner — the ConfigBatcher has full context.
**Cons:** Dual processing paths (v1 KVs for global/per-node, raw resources for selector-scoped).

#### Approach C: New intermediate model key type

Add a new model key type for selector-scoped config that includes the resource name and field name. The `configUpdateProcessor` emits these for selector-scoped FelixConfigurations. The ConfigBatcher collects them, evaluates selectors, and merges.

**Final Recommended Approach:**

1. **Extend `extractNode()` in `configurationprocessor.go`**: Currently, resource names that are not `"default"` and don't start with `"node."` return an error. Instead, for such names, we skip processing entirely (return empty list — no KVPairs). These resources will be handled by a new path.

2. **Add a new dispatcher registration in the ConfigBatcher**: Register for `model.ResourceKey{Kind: "FelixConfiguration"}` to receive raw FelixConfiguration updates. When a selector-scoped FelixConfiguration arrives, store it. Evaluate its selector against local node labels.

3. **In `maybeSendCachedConfig()`**: Merge configs in order: global → matching selector configs (alphabetically) → per-host.

4. **Watch Node resource for label changes**: The ConfigBatcher needs to register for node updates to track local node labels. When labels change, re-evaluate all selector-scoped configs and emit a config update if the set of matching configs changes.

### Step 5: Config Source Priority (`felix/config/`)

**File: `felix/config/config_params.go`**

Add a new `Source` between `DatastoreGlobal` and `DatastorePerHost`:

```go
const (
    Default Source = iota
    DatastoreGlobal
    DatastorePerSelector  // NEW
    DatastorePerHost
    ConfigFile
    EnvironmentVariable
    InternalOverride
)
```

Update `SourcesInDescendingOrder` accordingly.

Update the `configCallbacks` interface and EventSequencer to handle the new three-way config:

```go
type configCallbacks interface {
    OnConfigUpdate(globalConfig, selectorConfig, hostConfig map[string]string)
    OnDatastoreNotReady()
}
```

### Step 6: EventSequencer Changes (`felix/calc/`)

**File: `felix/calc/event_sequencer.go`**

Update `flushConfigUpdate()` to merge three config sources:
```go
globalChanged, err := buf.config.UpdateFrom(buf.pendingGlobalConfig, config.DatastoreGlobal)
selectorChanged, err := buf.config.UpdateFrom(buf.pendingSelectorConfig, config.DatastorePerSelector)
hostChanged, err := buf.config.UpdateFrom(buf.pendingHostConfig, config.DatastorePerHost)
```

### Step 7: Startup Path (`felix/daemon/`)

**File: `felix/daemon/daemon.go`**

Update `loadConfigFromDatastore()` to also load selector-scoped FelixConfigurations:
1. List ALL FelixConfiguration resources.
2. For each resource that is not `"default"` and doesn't start with `"node."`:
   - Parse the `NodeSelector`.
   - Evaluate against the local node's labels.
   - If it matches, collect its config.
3. Merge matching selector configs (alphabetically by name) into a `selectorConfig` map.
4. Apply with the new `DatastorePerSelector` source priority.

### Step 8: Typha Considerations

Typha already sends ALL FelixConfiguration resources to all Felix clients (no server-side filtering). This means:
- **No Typha changes needed** for the basic feature.
- Felix clients already receive all FelixConfiguration resources.
- The ConfigBatcher's client-side filtering approach extends naturally to selector-scoped configs.

However, for very large clusters with many selector-scoped FelixConfigurations, Typha could be enhanced later to filter based on node labels (optimization, not required for MVP).

### Step 9: Tests

1. **Unit tests for ConfigBatcher** (`felix/calc/config_batcher_test.go`):
   - Selector-scoped config matching
   - Multiple selector-scoped configs merging in alphabetical order
   - Node label changes causing config re-evaluation
   - Selector-scoped config + per-host config precedence
   - Invalid selector handling

2. **Unit tests for configUpdateProcessor** (`libcalico-go/lib/backend/syncersv1/updateprocessors/`):
   - `confignamev1:"-"` tag is properly skipped
   - Selector-scoped resource names are handled correctly

3. **Unit tests for validation** (`libcalico-go/lib/validator/v3/`):
   - NodeSelector forbidden on "default" resource
   - NodeSelector forbidden on "node.*" resources
   - Valid/invalid selector syntax

4. **Calc graph FV tests** (`felix/calc/calc_graph_fv_test.go`):
   - End-to-end config flow with selector-scoped FelixConfigurations

5. **Felix FV tests** (`felix/fv/`):
   - Create FelixConfiguration with nodeSelector
   - Verify it applies to matching nodes
   - Verify it doesn't apply to non-matching nodes
   - Verify precedence with global and per-host configs

### Step 10: Code Generation and Formatting

```bash
make generate          # Regenerate CRDs, deepcopy, protobuf
make fix-changed       # Fix formatting
```

## Files to Modify (Summary)

| File | Change |
|------|--------|
| `api/pkg/apis/projectcalico/v3/felixconfig.go` | Add `NodeSelector` field to `FelixConfigurationSpec` |
| `libcalico-go/lib/backend/syncersv1/updateprocessors/configurationprocessor.go` | Skip `confignamev1:"-"` fields; handle selector-scoped resource names |
| `libcalico-go/lib/validator/v3/validator.go` | Validate NodeSelector constraints |
| `felix/config/config_params.go` | Add `DatastorePerSelector` source |
| `felix/calc/config_batcher.go` | Major redesign: selector evaluation, node label tracking, three-way merge |
| `felix/calc/calc_graph.go` | Update `configCallbacks` interface, wire up node resource to ConfigBatcher |
| `felix/calc/event_sequencer.go` | Handle three-way config merge |
| `felix/daemon/daemon.go` | Update `loadConfigFromDatastore()` for selector-scoped configs |
| Tests: `*_test.go` files for all above | Comprehensive test coverage |

## Risks and Mitigations

1. **Config churn**: If many selector-scoped configs match a node, label changes could cause many config re-evaluations. **Mitigation**: ConfigBatcher already batches and coalesces updates.

2. **Ordering ambiguity**: Multiple selector-scoped configs may set the same field. **Mitigation**: Deterministic alphabetical ordering by resource name.

3. **Backwards compatibility**: Existing `"default"` and `"node.*"` resources continue to work exactly as before. The new feature is purely additive.

4. **Proto/API compatibility**: The `configCallbacks` interface change touches the internal calc graph contract. This is internal and not a public API concern.
