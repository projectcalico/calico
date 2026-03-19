---
name: test-whisker-api
description: Run manual API tests against the Whisker backend (flow filtering, filter hints, reporter, actions, staged actions, policy filters). Use after setting up a test environment with the setup-whisker-test-traffic skill.
---

## Overview

Runs a comprehensive suite of API tests against the Whisker backend to verify flow filtering, filter hints, reporter/action filters, policy filters (AND/OR logic), staged actions, and start time filtering. Reports PASS/FAIL for each test case.

## Prerequisites

- Whisker backend accessible (default: `http://localhost:8081/whisker-backend`)
- Active flow logs being generated (use the `setup-whisker-test-traffic` skill first)
- Flow logs should have been generating for at least 30 seconds before running tests

## API Reference

### Endpoints

| Endpoint | Purpose |
|---|---|
| `GET /whisker-backend/flows?watch=true&startTimeGte=-60` | Stream flow logs (SSE) |
| `GET /whisker-backend/flows-filter-hints?type=<TYPE>&pageSize=20` | Get filter hint values |

Both endpoints accept a `filters` query parameter as JSON. When using curl, pass the JSON inline with shell quoting (single quotes around the full URL). The backend accepts raw JSON in the query string.

### Filter JSON Structure

```json
{
  "source_names": [{"type": "Exact", "value": "pod-*"}],
  "source_namespaces": [{"type": "Exact", "value": "frontend"}],
  "dest_names": [{"type": "Exact", "value": "api-*"}],
  "dest_namespaces": [{"type": "Exact", "value": "backend"}],
  "protocols": [{"type": "Exact", "value": "tcp"}],
  "dest_ports": [{"type": "Exact", "value": 53}],
  "actions": ["Allow", "Deny", "Pass"],
  "pending_actions": ["Allow", "Deny"],
  "reporter": "Src",
  "policies": [
    {
      "kind": "CalicoNetworkPolicy",
      "tier": {"type": "Exact", "value": "security"},
      "name": {"type": "Exact", "value": "deny-db-to-frontend"},
      "namespace": {"type": "Exact", "value": "database"},
      "action": "Allow"
    }
  ]
}
```

Key rules:
- All fields are optional
- `reporter` is a single string value, NOT an array
- `actions` and `pending_actions` are string arrays
- `policies` is an array of objects; multiple objects = OR logic; fields within one object = AND logic
- `kind` in policy filters is a bare string (not a FilterMatch object)
- All other policy subfields (`tier`, `name`, `namespace`) use FilterMatch objects
- `dest_ports` uses FilterMatch with integer value: `{"type": "Exact", "value": 53}`
- FilterMatch types: `"Exact"` (equality) or `"Fuzzy"` (substring contains)

### Valid Filter Hint Types

`DestName`, `SourceName`, `DestNamespace`, `SourceNamespace`, `PolicyTier`, `PolicyName`, `PolicyKind`, `PolicyNamespace`

### Valid PolicyKind Values

`CalicoNetworkPolicy`, `GlobalNetworkPolicy`, `NetworkPolicy`, `StagedNetworkPolicy`, `StagedGlobalNetworkPolicy`, `StagedKubernetesNetworkPolicy`, `Profile`, `EndOfTier`, `ClusterNetworkPolicy`

### Valid Action Values

`Allow`, `Deny`, `Pass`

### Valid Reporter Values

`Src`, `Dst`

### Special Display Values

- Source/dest namespace `"-"` or `""` displays as `"Global"` in hints
- Source/dest name `"pub"` displays as `"PUBLIC NETWORK"`, `"pvt"` as `"PRIVATE NETWORK"`

### FlowResponse Structure

```json
{
  "start_time": "2026-03-19T14:30:00Z",
  "end_time": "2026-03-19T14:31:00Z",
  "action": "Allow",
  "source_name": "traffic-gen-*",
  "source_namespace": "frontend",
  "source_labels": "app=traffic-gen | role=client",
  "dest_name": "api-*",
  "dest_namespace": "backend",
  "dest_labels": "app=api | role=backend",
  "protocol": "tcp",
  "dest_port": 8080,
  "reporter": "Src",
  "policies": {
    "enforced": [
      {
        "kind": "CalicoNetworkPolicy",
        "name": "allow-frontend-to-backend",
        "namespace": "frontend",
        "tier": "platform",
        "action": "Allow",
        "policy_index": 0,
        "rule_index": 0,
        "trigger": null
      }
    ],
    "pending": [
      {
        "kind": "StagedGlobalNetworkPolicy",
        "name": "staged-allow-all",
        "namespace": "",
        "tier": "default",
        "action": "Allow",
        "policy_index": 0,
        "rule_index": 0,
        "trigger": null
      }
    ]
  },
  "packets_in": 100,
  "packets_out": 50,
  "bytes_in": 5000,
  "bytes_out": 2500
}
```

### Source Code Reference

| File | Purpose |
|---|---|
| `goldmane/proto/api.proto` | Proto definitions for all filter types and enums |
| `whisker-backend/pkg/apis/v1/flows.go` | Go types for FlowResponse, Filters, FilterMatch |
| `whisker-backend/pkg/handlers/v1/flows.go` | HTTP handler for /flows and /flows-filter-hints |
| `whisker-backend/pkg/handlers/v1/protoconvert.go` | Converts HTTP filter JSON to proto filters |
| `goldmane/pkg/types/filters.go` | Filter matching logic (Exact/Fuzzy) |

## Test Cases

Run all tests below. For `/flows` endpoints, always use `watch=true&startTimeGte=-60` and `curl --max-time 8`. Parse SSE `data:` lines from responses. Report PASS/FAIL for each with evidence.

### Group 1: Filter Hints

**TEST 1 (OS-T954): Filter hints return PolicyKind values**
```
GET /flows-filter-hints?type=PolicyKind&pageSize=20
```
Verify response includes valid policy kinds. Expected: at least `CalicoNetworkPolicy`, `GlobalNetworkPolicy`, `NetworkPolicy`, `StagedGlobalNetworkPolicy`, `StagedNetworkPolicy`. Check if `Profile` and `StagedKubernetesNetworkPolicy` are present.

**TEST 2 (OS-T955): Filter hints return PolicyTier values**
```
GET /flows-filter-hints?type=PolicyTier&pageSize=20
```
Verify returns available tiers. Expected (with setup-whisker-test-traffic): `compliance`, `security`, `platform`, `application`, `default`, `calico-system`.

**TEST 3 (OS-T956): Filter hints return PolicyNamespace values**
```
GET /flows-filter-hints?type=PolicyNamespace&pageSize=20
```
Verify namespaces where policies exist are returned. Verify empty string `""` appears for GlobalNetworkPolicies.

**TEST 4 (OS-T957): Filter hints return PolicyName values**
```
GET /flows-filter-hints?type=PolicyName&pageSize=20
```
Verify returns policy names present in actual flow logs. Note: only policies referenced in flows will appear, not all cluster policies.

**TEST 5 (OS-T958): Cascading filter hints respect selections**
Step 1 — Filter by Kind=NetworkPolicy, request PolicyNamespace:
```
GET /flows-filter-hints?type=PolicyNamespace&pageSize=20&filters={"policies":[{"kind":"NetworkPolicy"}]}
```
Verify only namespaces with K8s NetworkPolicy flows are shown (should be a small subset).

Step 2 — Filter by Kind=NetworkPolicy AND namespace, request PolicyName:
```
GET /flows-filter-hints?type=PolicyName&pageSize=20&filters={"policies":[{"kind":"NetworkPolicy","namespace":{"type":"Exact","value":"frontend"}}]}
```
Verify only matching policy names appear.

Step 3 — Compare: filter by Kind=CalicoNetworkPolicy, request PolicyNamespace:
```
GET /flows-filter-hints?type=PolicyNamespace&pageSize=20&filters={"policies":[{"kind":"CalicoNetworkPolicy"}]}
```
Verify more namespaces appear than for K8s NetworkPolicy.

**TEST 6 (OS-T959): Filter hints with active flow filters**
```
GET /flows-filter-hints?type=PolicyName&pageSize=20&filters={"policies":[{"kind":"Profile"}]}
```
Verify hints respect the filter context. Note: the backend returns all policy names from flows that have a Profile policy hit (not just Profile names themselves). This is because a single flow can have multiple policy hits of different kinds.

### Group 2: Flow Filtering by Policy

**TEST 7 (OS-T960): Filter flows by policy kind**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"NetworkPolicy"}]}
```
Verify every returned flow has at least one policy with `kind=NetworkPolicy` in enforced or pending arrays.

**TEST 8 (OS-T961): Filter flows by policy tier**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"tier":{"type":"Exact","value":"security"}}]}
```
Verify every flow has at least one policy in the `security` tier.

**TEST 9 (OS-T962): Filter flows by policy namespace**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"namespace":{"type":"Exact","value":"database"}}]}
```
Verify every flow has at least one policy with `namespace=database`.

**TEST 10 (OS-T963): Filter flows by policy name**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"name":{"type":"Exact","value":"deny-db-to-frontend"}}]}
```
Verify every flow has the named policy in enforced or pending.

**TEST 11 (OS-T964): AND logic within single policy object**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"CalicoNetworkPolicy","namespace":{"type":"Exact","value":"database"}}]}
```
Verify every flow has a policy matching BOTH kind=CalicoNetworkPolicy AND namespace=database on the same policy hit.

**TEST 12 (OS-T965): OR logic across policy array objects**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"Profile"},{"kind":"GlobalNetworkPolicy"}]}
```
Verify flows matching EITHER kind=Profile OR kind=GlobalNetworkPolicy are returned. Both kinds should be present across the result set.

**TEST 13 (OS-T966): Combined AND+OR policy filter logic**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"CalicoNetworkPolicy","namespace":{"type":"Exact","value":"frontend"}},{"kind":"CalicoNetworkPolicy","namespace":{"type":"Exact","value":"database"}}]}
```
Verify flows from (CalicoNetworkPolicy+frontend) OR (CalicoNetworkPolicy+database) are returned.

**TEST 14 (OS-T967): No matching policies filter (Profile)**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"Profile"}]}
```
Verify only flows with Profile policy hits are returned. Profile names look like `kns.<namespace>`.

**TEST 15 (OS-T968): Filter by staged policy kind**
```
GET /flows?watch=true&startTimeGte=-60&filters={"policies":[{"kind":"StagedGlobalNetworkPolicy"}]}
```
Verify returned flows have StagedGlobalNetworkPolicy in their policies (typically in the `pending` array).

### Group 3: Reporter & Action Filters

**TEST 16 (OS-T970): Reporter filter by Src**
```
GET /flows?watch=true&startTimeGte=-60&filters={"reporter":"Src"}
```
Verify ALL returned flows have `"reporter":"Src"`. Zero should have `"reporter":"Dst"`.

**TEST 17 (OS-T971): Reporter filter by Dst**
```
GET /flows?watch=true&startTimeGte=-60&filters={"reporter":"Dst"}
```
Verify ALL returned flows have `"reporter":"Dst"`.

**TEST 18 (OS-T972): Actions filter - Allow**
```
GET /flows?watch=true&startTimeGte=-60&filters={"actions":["Allow"]}
```
Verify all flows have `"action":"Allow"`.

**TEST 19 (OS-T973): Actions filter - Deny**
```
GET /flows?watch=true&startTimeGte=-60&filters={"actions":["Deny"]}
```
Verify all flows have `"action":"Deny"`.

**TEST 20 (OS-T974): Pending/staged actions filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"pending_actions":["Deny"]}
```
Verify returned flows have a Deny action in their `policies.pending` array.

**TEST 21 (OS-T975): Combine action + staged action filters**
```
GET /flows?watch=true&startTimeGte=-60&filters={"actions":["Allow"],"pending_actions":["Deny"]}
```
Verify flows are currently allowed (`action=Allow`) AND have a staged Deny in pending policies.

### Group 4: Start Time & Combined Filters

**TEST 22 (OS-T976): Start time filter**
Compare flow counts across time windows:
```
GET /flows?watch=true&startTimeGte=-60    (last 1 min)
GET /flows?watch=true&startTimeGte=-300   (last 5 min)
GET /flows?watch=true&startTimeGte=-30    (last 30 sec)
```
Verify: count(-300) >= count(-60) >= count(-30). Note: very small values (< ~10s) may return unexpected results due to 15-second aggregation buckets.

**TEST 23 (OS-T969): Reporter field present in all flows**
```
GET /flows?watch=true&startTimeGte=-60
```
Verify every flow has a `"reporter"` field with value `"Src"` or `"Dst"`.

**TEST 24: Combined reporter + action filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"actions":["Deny"],"reporter":"Src"}
```
Verify all returned flows have BOTH action=Deny AND reporter=Src.

### Group 5: Regression - Existing Filters

**TEST 25: Source namespace filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"source_namespaces":[{"type":"Exact","value":"frontend"}]}
```
Verify all flows have `source_namespace=frontend`.

**TEST 26: Dest namespace filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"dest_namespaces":[{"type":"Exact","value":"database"}]}
```
Verify all flows have `dest_namespace=database`.

**TEST 27: Dest port filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"dest_ports":[{"type":"Exact","value":53}]}
```
Verify all flows have `dest_port=53`.

**TEST 28: Combined source + dest namespace filter**
```
GET /flows?watch=true&startTimeGte=-60&filters={"source_namespaces":[{"type":"Exact","value":"frontend"}],"dest_namespaces":[{"type":"Exact","value":"backend"}]}
```
Verify all flows have source_namespace=frontend AND dest_namespace=backend.

**TEST 29: SourceNamespace filter hints**
```
GET /flows-filter-hints?type=SourceNamespace&pageSize=20
```
Verify returns reasonable namespace list.

**TEST 30: DestNamespace filter hints**
```
GET /flows-filter-hints?type=DestNamespace&pageSize=20
```
Verify returns reasonable namespace list.

### Group 6: Pod Health (Regression)

**TEST 31 (OS-T984): calico-system pods healthy**
```bash
kubectl get pods -n calico-system
```
Verify all pods are Running. No CrashLoopBackOff. Goldmane and whisker pods specifically.

**TEST 32 (OS-T985): No unexpected restarts**
```bash
kubectl get pods -n calico-system
```
Verify RESTARTS column is 0 or very low for all pods.

## Running the Tests

Run tests in parallel by group for speed. Use agents for each group:
- Group 1 (Tests 1-6): Filter hints
- Group 2 (Tests 7-15): Policy flow filtering
- Group 3 (Tests 16-21): Reporter & action filters
- Group 4 (Tests 22-24): Start time & combined
- Group 5 (Tests 25-30): Regression existing filters
- Group 6 (Tests 31-32): Pod health

For each test:
1. Execute the curl/kubectl command
2. Parse the response
3. Validate against the expected behavior
4. Report PASS or FAIL with evidence (flow count, violation count, sample data)

## Output Format

Present results as a summary table:

| # | Test Case | ID | Result | Notes |
|---|---|---|---|---|
| 1 | PolicyKind hints | OS-T954 | PASS/FAIL | details |
| ... | ... | ... | ... | ... |

Include totals: X PASS, Y FAIL out of Z tests.

## Known Issues / Quirks

- `Profile` and `StagedKubernetesNetworkPolicy` may not appear in PolicyKind hints even when present in flows
- Cascading filter hints for Kind=Profile returns all policy names from flows containing Profile hits (not just Profile names)
- Start time values < ~10 seconds may behave unexpectedly due to 15-second flow aggregation buckets
- `dest_ports` requires FilterMatch format `{"type":"Exact","value":53}`, not bare integers
- `Port` is NOT a valid filter hint type (only the types listed above are valid)
