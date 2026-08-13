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

### Two narrow registries, not one wide one

Filtering has three separable concerns — what the URL carries,
how values are serialized for the backend, and how chips look —
and [`src/utils/filters/`](src/utils/filters/) keeps them in
separate modules rather than one entry per filter declaring all
three. Each table has only required fields, so "which filters
have this?" is answered by membership rather than by a `?:`.

**[`urlKeys.ts`](src/utils/filters/urlKeys.ts) — the URL contract.**
`urlFilterKeys` is an explicit list of the 11 search params,
written out rather than derived: users share filtered links, so
the set is a public contract and worth stating literally.
`FilterKeys` gives each key a named
handle, derived from the list so it cannot drift.
`urlValueParsers` holds decoders for keys whose value is not a
plain string list — currently just `policy`'s JSON blob.

**[`flowsFilter.ts`](src/utils/filters/flowsFilter.ts) — serialization.**
`flowLogFilterMap` maps each URL param to the `FlowsFilter` key it
lands under (`flowsFilterKey`) and the transform that shapes its
value (`toFilterValue`). It is declared
`satisfies Record<FlowsFilterId, unknown>` where
`FlowsFilterId = Exclude<UrlFilterKey, 'start_time'>`, so **a URL
key with no wire mapping is a type error** — the historical
`pending_action` crash cannot be written. `start_time` is absent
from the table rather than present with a missing field, because
it reaches the backend as `startTimeGte` instead.

**[`dataFilters.ts`](src/utils/filters/dataFilters.ts) — autocomplete fetching.**
`dataFilters` covers the filters whose options come from the
backend rather than a fixed list, which is exactly the filters
that fetch: the four list chips and the four policy sub-selects.
Each entry carries
`hintType` (`?type=`), `pageSize`, and `toSearch`, which returns
the search term as a complete `FlowsFilter` fragment — so the
nesting (policy searches go under `policies`) is checked against
the wire type instead of assembled by the caller. `reporter` and
`policy` are deliberately absent: reporter's option list is fixed,
policy is populated through its sub-selects, and goldmane's
`FilterType` enum (`goldmane/proto/api.proto`) has no member for
either, so a request would be rejected anyway. `DataFilterId` —
the table's key set — is the id type the fetching hook accepts.

Chip identity and labels are **not** in these tables; they live
next to the bar in
[`TableFilters/filters.ts`](src/features/flowLogs/components/TableFilters/filters.ts).

**Review notes**

- Adding a URL param means adding it to `urlFilterKeys` _and_
  `flowLogFilterMap`; the compiler enforces the second. Adding a
  fetching filter means a `dataFilters` entry. Do not add an
  optional field to a spec to cover one filter — that is how the
  old single registry accumulated ten of them; give the filter its
  own component or module instead.
- Bar order lives in `tableLevelFilterIds`
  (`TableFilters/filters.ts`) and is pinned by e2e screenshots.
  `urlFilterKeys` is kept in the same order for readability, but
  its order is not load-bearing.
- `flowsFilterKey` values must be unique and must exist in
  `FlowsFilter` ([`src/types/api.ts`](src/types/api.ts)), which
  mirrors whisker-backend's `Filters` struct
  (`whisker-backend/pkg/apis/v1/flows.go`) — keep the two in
  sync when the backend grows a filter. Note `FlowsFilter` has
  three shapes, not one: match lists, a bare `reporter` enum, and
  bare `actions`/`pending_actions` enum lists.
- The structural invariants (unique wire keys, the exact URL key
  surface, the exact `dataFilters` set, and that a list filter
  searches under the same key its selection uses) are pinned in
  [`src/utils/filters/__tests__/filters.test.ts`](src/utils/filters/__tests__/filters.test.ts).

### How one spec reaches the two backend endpoints

The `filters` JSON blob is built by two named builders in
`flowsFilter.ts`, sharing one spec-iterating core:

- `toFlowLogFilterQuery(values)` — the **stream**:
  `GET flows?watch=true&filters=<blob>&startTimeGte=<n>`
  (`useFlowLogsStream` in
  [`src/features/flowLogs/api/index.ts`](src/features/flowLogs/api/index.ts)).
  Each selected URL value lands under its `flowsFilterKey`,
  shaped by `toFilterValue`. Keys with no spec are skipped —
  `start_time` never joins the blob; it becomes the `startTimeGte`
  query param instead (minutes → negative seconds via
  `parseStartTime`/`transformStartTime`).
- `toDataFilterQuery(values, filterId, search?)` — a **hint
  request**: `GET flows-filter-hints?type=<hintType>&page=&pageSize=&filters=<blob>`.
  The blob carries the _other_ active filters as narrowing
  context — the filter being populated is excluded so users can
  widen their selection — merged with the fragment its
  `dataFilters` entry's `toSearch` returns for the typed term.

**Review notes**

- The blob content is a backend contract pinned byte-for-byte by
  [`e2e/tests/backend-contract.spec.ts`](e2e/tests/backend-contract.spec.ts)
  and the wire-format corpus in `filters.test.ts`. JSON _key
  order_ is not part of the contract (both compare parsed
  objects), but shapes and values are.
- Folding a heterogeneous spec table loses the key-to-value type
  correlation, so `toFlowLogFilter` erases the spec type once, in
  one commented place. Do not spread that cast outwards into the
  spec definitions — they are the part that is checked.
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
└── TableFilters (no props)     reads/writes useFlowLogsUrlFilters
    ├── PolicyOmniFilter        bespoke; PolicySelect x4 fetch via useOmniFilterOptions
    ├── ListOmniFilter x4       generic chips, self-fetching
    ├── ReporterOmniFilter      fixed radio options; never fetches
    ├── PortOmniFilter          bespoke; writes dest_port + protocol together
    ├── ActionOmniFilter        bespoke; writes action + staged_action together
    └── StartTimeOmniFilter     bespoke; start_time -> stream lookback
```

`TableFilters` declares what it renders in
[`./filters.ts`](src/features/flowLogs/components/TableFilters/filters.ts):
`tableLevelFilterIds` (9 chips, in bar order, with the four
fetching chips as the nested `tableLevelDataFilterIds` block) and
`filterLabels`. That set is _not_ `urlFilterKeys` — `protocol` is
owned by the Port chip and `staged_action` by the Action chip, so
neither is a chip of its own.

`useOmniFilterOptions(filterId, { narrowByActiveFilters })`
([`src/hooks/omniFilters.ts`](src/hooks/omniFilters.ts)) is the
one fetching hook: it reads the URL state, builds the narrowed
hint query, debounces searches (500 ms, with a typing spinner
folded into `isLoading`), and pages via react-query's
`useInfiniteQuery`. Fetching is lazy — nothing is requested
until a popover first opens (`enabled: query !== null`), and
re-opening with the same query refetches.

[`ListOmniFilter`](src/features/flowLogs/components/ListOmniFilter/index.tsx)
is the generic chip: one component for every
`tableLevelDataFilterIds` entry,
self-fetching, writing its selection to the URL. It has no
per-filter escape hatch — a filter that needs different behaviour
gets its own component, which is why `ReporterOmniFilter` exists
rather than a prop-override bag on the generic chip. Bespoke chips
own their popover UI and write one or more URL params via
`setFilter`/`setMultiFilter`.

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
  to decide chip visibility and whether to show Reset. Chips must
  use the `filterLabel` they are handed rather than reaching for a
  label of their own — two sources drift, and did.
- `src/libs/tigera/ui-components/` is a vendored copy of a
  shared Tigera library. Wrap it; do not change its public API.
- Hint-request narrowing ("do not constrain a list by its own
  selection") is pinned by `backend-contract.spec.ts` and by
  `ListOmniFilter`/`useOmniFilterOptions` unit tests.

## 2. Adding a filter

**Standard list filter** (paged autocomplete chip) — four
one-liners, then a test:

1. `urlKeys.ts`: add the param to `urlFilterKeys`.
2. `flowsFilter.ts`: add
   `my_filter: flowsFilterSpec('my_filters', transformToExactMatches)`
   to `flowLogFilterMap`.
   The compiler requires this. (The wire key must exist in
   `FlowsFilter` / the backend `Filters` struct.)
3. `dataFilters.ts`: add `hintType`, `pageSize` and a `toSearch`
   returning `{ my_filters: [fuzzy(search)] }`. (The hint type
   must exist in goldmane's `FilterType` enum.)
4. `TableFilters/filters.ts`: add it to `tableLevelDataFilterIds`
   — positioned where it should appear in the bar — and
   `filterLabels`. `TableFilters` renders a `ListOmniFilter` for
   every entry in that list.
5. Add one row to the wire-format corpus in
   `src/utils/filters/__tests__/filters.test.ts`, and ideally a
   deep-link case in `e2e/tests/backend-contract.spec.ts`.

**Bespoke filter**: add a `urlFilterKeys` + `flowLogFilterMap`
entry per URL param it owns, build the chip from the
`OmniFilterContainer`/`Trigger`/`Content`/`Body` parts plus the
shared `OmniFilterFooter`, wire it to
`setFilter`/`setMultiFilter`, and hand-place it in `TableFilters`
with a `tableLevelFilterIds` entry for whichever param names the
chip.
Give it `dataFilters` entries — without `urlFilterKeys` entries —
for any autocomplete sources used inside it (see the policy
sub-selects).

## 3. Test map

| Layer     | What it pins                                        | Where                                                                                                   |
| --------- | --------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Unit      | URL ↔ state ↔ wire chain, registry invariants     | `src/utils/filters/__tests__/filters.test.ts`                                                           |
| Unit      | URL hook behaviour                                  | `src/hooks/__tests__/useFlowLogsUrlFilters.test.ts`                                                     |
| Unit      | hint fetching, narrowing, debounce                  | `src/hooks/__tests__/omniFilters.test.ts`, `src/features/flowLogs/components/ListOmniFilter/__tests__/` |
| Component | bar wiring → URL writes, chip manifest              | `src/features/flowLogs/components/TableFilters/__tests__/`                                              |
| Component | reporter's fixed options, and that it never fetches | `src/features/flowLogs/components/ReporterOmniFilter/__tests__/`                                        |
| e2e       | exact backend `filters` blob, narrowing             | `e2e/tests/backend-contract.spec.ts`                                                                    |
| e2e       | apply/deep-link/reset flows                         | `e2e/tests/filters.spec.ts`                                                                             |
| e2e       | visual baselines (bar order, popovers)              | `e2e/tests/visual.spec.ts` + `__screenshots__/`                                                         |

The jest suite mocks aggressively, so the e2e suites are the
real behaviour lock for anything wire- or pixel-shaped. Run them
with `yarn e2e` (see [`e2e/README.md`](e2e/README.md)).

## Keep this in sync

A PR that changes the filtering data flow — either registry's
shape, the URL param surface, wire mapping, narrowing semantics,
or where fetching happens — must update this document in the same
PR.
Exemptions follow the repo rule in
[`.claude/CLAUDE.md`](../.claude/CLAUDE.md): bug fixes restoring
documented behaviour, mechanical refactors, comment edits,
dependency bumps.
