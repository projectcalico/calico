# Whisker — Architecture & Design

Whisker is the flow-log UI: a TypeScript/React single-page app
(Chakra UI, react-query, react-router, built with rsbuild) served
alongside [`whisker-backend`](../whisker-backend/), which exposes
the flows APIs over goldmane. The app has one page —
`FlowLogsPage` — that streams flow logs over SSE and lets the
user filter them.

This document covers the app's architecture with a focus on
filtering, which is where most of the moving parts live. For
operational guidance (build, test, lint) see
[`README.md`](README.md) and [`e2e/README.md`](e2e/README.md).

## 1. Filtering architecture

### The URL is the filter state

There is no filter store or context. The URL search params _are_
the state: `useFlowLogsUrlFilters`
([`src/hooks/useFlowLogsUrlFilters.tsx`](src/hooks/useFlowLogsUrlFilters.tsx))
parses them into `SelectedOmniFilterValues` and exposes
`setFilter`/`setMultiFilter`/`clearFilters` which write back via
react-router. Deep links, back/forward navigation, and shareable
filtered views fall out for free, and any component at any depth
can read or write filter state by calling the hook — no prop
drilling.

**Review notes**

- Do not introduce a second store (context, redux, component
  state) for filter values; two sources of truth will drift. The
  URL param format is a public contract — people share links —
  so renaming or re-encoding a param is a breaking change and
  needs an explicit decision, not refactor collateral.
- Non-filter params (`utm_source`, etc.) must survive filter
  writes and resets; `buildSearchParamsFromFilters` only touches
  keys it is given.

### The filter registry is the single source of truth

Every filter is one entry in `OmniFilterProperties`
([`src/utils/omniFilter.ts`](src/utils/omniFilter.ts)). An entry
declares everything about a filter:

| Field                            | Meaning                                                                                                                                                                                                 | Consumed by                             |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| entry key                        | the URL search param (non-`hint` kinds) and React key                                                                                                                                                   | `useFlowLogsUrlFilters`, the filter bar |
| `kind`                           | `list` (generic paged autocomplete chip) / `static` (generic chip, fixed options) / `custom` (bespoke chip owns the param) / `hint` (not a URL param; an autocomplete source used inside a custom chip) | type derivation, bar rendering          |
| `label`                          | chip label                                                                                                                                                                                              | UI                                      |
| `filterHintsKey`                 | wire key in the `filters` JSON blob; absent for stream-only params (`start_time`)                                                                                                                       | both endpoints, below                   |
| `transformToFilterHintRequest`   | selected URL values → wire value                                                                                                                                                                        | both endpoints                          |
| `hintType`                       | `?type=` for `flows-filter-hints`                                                                                                                                                                       | hint fetching                           |
| `limit`                          | hint page size                                                                                                                                                                                          | hint fetching                           |
| `transformToFilterSearchRequest` | search text → fuzzy fragment                                                                                                                                                                            | hint fetching                           |
| `parentFilterKey`                | wire key the search fragment nests under (policy sub-filters)                                                                                                                                           | hint fetching                           |
| `parseUrlValue`                  | decode a non-plain URL value (policy's JSON blob)                                                                                                                                                       | URL parsing                             |
| `filterComponentProps`           | prop overrides for the generic chip (reporter's radio setup)                                                                                                                                            | `ListOmniFilter`                        |

Everything else is **derived** from the registry — the key-type
unions (`FilterId`, `ListFilterId`, `UrlFilterKey`,
`FilterHintKey`, …) via mapped types over the literal `kind`
fields, and the runtime lists (`listFilterIds`, `urlFilterKeys`,
…) by filtering the entries. There are no hand-maintained
parallel key sets. This is what makes a class of bug impossible
by construction: a URL key without wire mapping (the historical
`pending_action` crash) cannot exist, because the URL keys _are_
the registry keys.

**Review notes**

- A new filter must be a registry entry first; if a PR adds a
  filter by editing multiple key lists, something has regressed.
- Registry object order is meaningful: `list`/`static` entries
  render in the bar in object order (pinned by e2e screenshots).
- `filterHintsKey` values must be unique and must exist in
  `FlowsFilter` ([`src/types/api.ts`](src/types/api.ts)), which
  mirrors whisker-backend's `Filters` struct
  (`whisker-backend/pkg/apis/v1/flows.go`) — keep the two in
  sync when the backend grows a filter.
- The structural invariants (unique wire keys, every fetching
  filter has a `hintType`, the exact URL key surface) are pinned
  in [`src/utils/__tests__/omniFilter.test.ts`](src/utils/__tests__/omniFilter.test.ts).

### How one registry entry reaches the two backend endpoints

The `filters` JSON blob is built by two named builders in
`omniFilter.ts`, sharing one registry-iterating core:

- `toFlowsFilterQuery(values)` — the **stream**:
  `GET flows?watch=true&filters=<blob>&startTimeGte=<n>`
  (`useFlowLogsStream` in
  [`src/features/flowLogs/api/index.ts`](src/features/flowLogs/api/index.ts)).
  Each selected URL value lands under its `filterHintsKey`,
  shaped by `transformToFilterHintRequest`. Entries without a
  wire key are skipped — `start_time` never joins the blob; it
  becomes the `startTimeGte` query param instead (minutes →
  negative seconds via `parseStartTime`/`transformStartTime`).
- `toHintFilterQuery(values, filterId, search?)` — a **hint
  request**: `GET flows-filter-hints?type=<hintType>&page=&pageSize=&filters=<blob>`.
  The blob carries the _other_ active filters as narrowing
  context — the filter being populated is excluded so users can
  widen their selection — plus the typed search term as a fuzzy
  fragment under `parentFilterKey ?? filterHintsKey`.

**Review notes**

- The blob content is a backend contract pinned byte-for-byte by
  [`e2e/tests/backend-contract.spec.ts`](e2e/tests/backend-contract.spec.ts)
  and the wire-format corpus in `omniFilter.test.ts`. JSON _key
  order_ is not part of the contract (both compare parsed
  objects), but shapes and values are.
- The blob is deliberately **not** URL-encoded in the stream
  path (`objToQueryStr`): EventSource encodes the URL itself,
  and double-encoding is a silent no-results bug.
- Known quirk, pinned on purpose: `dest_port` coerces via
  `Number()` and drops falsy results, so port `0` and non-numeric
  input silently vanish from the query. Changing that is a
  deliberate decision, not refactor collateral.

### Filter components fetch their own data

Fetching lives next to the filters, not in the page:

```
FlowLogsPage                    URL filters -> SSE stream only
└── OmniFilters (no props)      reads/writes useFlowLogsUrlFilters
    ├── PolicyOmniFilter        custom; PolicySelect x4 fetch via useOmniFilterOptions
    ├── ListOmniFilter x5       generic chips (4 list + reporter), self-fetching
    ├── PortOmniFilter          custom; writes dest_port + protocol together
    ├── ActionOmniFilter        custom; writes action + staged_action together
    └── StartTimeOmniFilter     custom; start_time -> stream lookback
```

`useOmniFilterOptions(filterId, { narrowByActiveFilters })`
([`src/hooks/omniFilters.ts`](src/hooks/omniFilters.ts)) is the
one fetching hook: it reads the URL state, builds the narrowed
hint query, debounces searches (500 ms, with a typing spinner
folded into `isLoading`), and pages via react-query's
`useInfiniteQuery`. Fetching is lazy — nothing is requested
until a popover first opens (`enabled: query !== null`), and
re-opening with the same query refetches.

[`ListOmniFilter`](src/features/flowLogs/components/ListOmniFilter/index.tsx)
is the generic chip: registry-driven, self-fetching, writing its
selection to the URL. `static` filters (reporter) render through
it too, overriding the fetch behaviour via their registry
`filterComponentProps`. Custom chips own their popover UI and
write one or more URL params via `setFilter`/`setMultiFilter`.

One deliberate asymmetry: the policy sub-selects
(`PolicySelect`) pass `narrowByActiveFilters: false`, so policy
lookups are _not_ narrowed by the other active filters, unlike
the list chips. That preserves long-standing behaviour; flipping
the flag is a one-line change but a user-visible product
decision.

**Review notes**

- Chips receive `filterId`, `filterLabel`, and `selectedFilters`
  as props even though they could read the URL themselves: the
  vendored `OmniFilterList` inspects its direct children's props
  to decide chip visibility and whether to show Reset.
- `src/libs/tigera/ui-components/` is a vendored copy of a
  shared Tigera library. Wrap it; do not change its public API.
- Hint-request narrowing ("do not constrain a list by its own
  selection") is pinned by `backend-contract.spec.ts` and by
  `ListOmniFilter`/`useOmniFilterOptions` unit tests.

## 2. Adding a filter

**Standard list filter** (paged autocomplete chip):

1. Add one entry to `OmniFilterProperties`:
   `my_filter: listFilter('My Filter', 'MyHintType', 'my_filters')`.
   URL round-trip, chip rendering, narrowed autocomplete, and the
   stream blob all derive from it. (The wire key must exist in
   `FlowsFilter` / the backend `Filters` struct, and the hint
   type in the backend's `FilterHintsPath` handling.)
2. Add one row to the wire-format corpus in
   `src/utils/__tests__/omniFilter.test.ts`, and ideally a
   deep-link case in `e2e/tests/backend-contract.spec.ts`.

**Custom filter**: add a `kind: 'custom'` entry per URL param it
owns, build the chip from the `OmniFilterContainer`/`Trigger`/
`Content`/`Body` parts plus the shared `OmniFilterFooter`, wire
it to `setFilter`/`setMultiFilter`, and hand-place it in
`OmniFilters`. Use `kind: 'hint'` entries for any autocomplete
sources used inside it (see the policy sub-filters).

## 3. Test map

| Layer     | What it pins                                    | Where                                                                                                   |
| --------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Unit      | URL ↔ state ↔ wire chain, registry invariants | `src/utils/__tests__/omniFilter.test.ts`                                                                |
| Unit      | URL hook behaviour                              | `src/hooks/__tests__/useFlowLogsUrlFilters.test.ts`                                                     |
| Unit      | hint fetching, narrowing, debounce              | `src/hooks/__tests__/omniFilters.test.ts`, `src/features/flowLogs/components/ListOmniFilter/__tests__/` |
| Component | bar wiring → URL writes                         | `src/features/flowLogs/components/OmniFilters/__tests__/`                                               |
| e2e       | exact backend `filters` blob, narrowing         | `e2e/tests/backend-contract.spec.ts`                                                                    |
| e2e       | apply/deep-link/reset flows                     | `e2e/tests/filters.spec.ts`                                                                             |
| e2e       | visual baselines (bar order, popovers)          | `e2e/tests/visual.spec.ts` + `__screenshots__/`                                                         |

The jest suite mocks aggressively, so the e2e suites are the
real behaviour lock for anything wire- or pixel-shaped. Run them
with `yarn e2e` (see [`e2e/README.md`](e2e/README.md)).

## Keep this in sync

A PR that changes the filtering data flow — the registry shape,
URL param surface, wire mapping, narrowing semantics, or where
fetching happens — must update this document in the same PR.
Exemptions follow the repo rule in
[`.claude/CLAUDE.md`](../.claude/CLAUDE.md): bug fixes restoring
documented behaviour, mechanical refactors, comment edits,
dependency bumps.
