---
name: whisker-add-filter
description: Adds a new filter chip to the Whisker flow-logs UI — either a data filter (backend-fetched autocomplete) or a static filter (fixed options). Use when asked to add, extend, or wire up a filter in whisker's filter bar.
---

## Read first

[`whisker/DESIGN.md`](../../../whisker/DESIGN.md) §1 is the authoritative
description of the filtering architecture and its invariants. Read it before
touching any registry — this skill is the operational walkthrough; the design
doc is the contract.

The load-bearing facts:

- **The URL is the filter state.** No store, no context. `useFlowLogsUrlFilters`
  parses search params; chips write back with `setFilter`/`setMultiFilter`.
  URL param names are a public contract (people share links) — choose the
  param name deliberately, and never rename an existing one as refactor
  collateral.
- **Three narrow registries**, each owning one concern:
  | Registry | File | Owns |
  |---|---|---|
  | `urlFilterKeys` | `whisker/src/utils/filters/urlKeys.ts` | which search params exist |
  | `flowLogFilterMap` | `whisker/src/utils/filters/flowsFilter.ts` | URL param → backend `FlowsFilter` key + value transform |
  | `dataFilters` | `whisker/src/utils/filters/dataFilters.ts` | autocomplete hint fetching (fetching filters only) |

  Chip identity, bar order, and labels live separately, next to the bar:
  `whisker/src/features/flowLogs/components/TableFilters/filters.ts`.
- **Membership answers "does this filter X?"** — every field in every registry
  entry is required. Do NOT add an optional field to a spec type to cover one
  filter's quirk; that is how the old single registry rotted. A filter that
  needs different behaviour gets its own component or module.

## Decide which kind of filter you are adding

1. **Data filter** — options come from the backend
   (`GET flows-filter-hints`), paged, searchable. Examples: source/dest
   namespace and name. Uses the generic `ListOmniFilter` — **no new component
   needed**.
2. **Static filter** — options are a fixed list known at build time, never
   fetches. Example: `ReporterOmniFilter` (Source/Destination radio). Needs a
   small bespoke component.
3. **Bespoke multi-param filter** — owns several URL params or custom popover
   UI (Port+Protocol, Action+StagedAction, policy). Follow the static-filter
   steps but add one `urlFilterKeys`/`flowLogFilterMap` entry per param it
   owns, use `setMultiFilter`, and model the component on `PortOmniFilter` or
   `ActionOmniFilter`. If it embeds autocomplete sub-selects, give those
   `dataFilters` entries *without* `urlFilterKeys` entries (see
   `PolicyOmniFilter`'s `PolicySelect`).

## Backend prerequisites — check before writing any UI code

- The wire key must exist in `FlowsFilter` (`whisker/src/types/api.ts`), which
  mirrors whisker-backend's `Filters` struct
  (`whisker-backend/pkg/apis/v1/flows.go`). If the backend doesn't have the
  field yet, that PR comes first (or the same PR grows both).
- Data filters only: the hint type must exist in goldmane's `FilterType` enum
  (`goldmane/proto/api.proto`) and in whisker-backend's hint handling.
  Goldmane rejects requests for unknown types — this is why `reporter` and
  `policy` deliberately have no `dataFilters` entry.

## Steps — data filter

Four one-line registry entries, a chip position, then tests.

1. **`whisker/src/utils/filters/urlKeys.ts`** — add the param to
   `urlFilterKeys` (snake_case, matching its neighbours). Keep the list in the
   same order as the bar for readability (order here is not load-bearing).
2. **`whisker/src/utils/filters/flowsFilter.ts`** — add to `flowLogFilterMap`:
   ```ts
   my_filter: flowsFilterSpec('my_filters', transformToExactMatches),
   ```
   The `satisfies Record<FlowsFilterId, unknown>` clause makes this
   **compiler-enforced**: a URL key with no wire mapping is a type error.
   Reuse an existing transform (`transformToExactMatches`,
   `transformToPortMatches`, `transformToHeadValue`, `transformToHeadList`)
   before writing a new one.
3. **`whisker/src/utils/filters/dataFilters.ts`** — add the fetch spec:
   ```ts
   my_filter: {
       hintType: 'MyHintType',        // goldmane FilterType member
       pageSize: requestPageSize,
       toSearch: (search) => ({ my_filters: [fuzzy(search)] }),
   },
   ```
   `toSearch` returns a complete `FlowsFilter` fragment so the nesting is
   checked against the wire type. A list filter must search under the same key
   its selection uses — a unit test pins this.
4. **`whisker/src/features/flowLogs/components/TableFilters/filters.ts`** —
   add the id to `tableLevelDataFilterIds` at its bar position, and a label to
   `filterLabels`. `TableFilters` renders a `ListOmniFilter` for every entry
   in that list automatically — do not touch `TableFilters/index.tsx`.

That's the whole implementation. `ListOmniFilter` + `useOmniFilterOptions`
handle fetching, 500 ms search debounce, paging, narrowing by the other active
filters, and URL writes.

## Steps — static filter

1. **`urlKeys.ts` + `flowsFilter.ts`** — same as steps 1–2 above. Single-value
   filters typically use `transformToHeadValue` (bare value) or
   `transformToHeadList` (single-element list) — match the shape of the
   backend field. No `dataFilters` entry: absence from that table is what
   marks the filter as non-fetching, and the registry-invariant test
   enumerates the exact set.
2. **Create the component** — model it on
   `whisker/src/features/flowLogs/components/ReporterOmniFilter/index.tsx`:
   a fixed `options: OmniFilterOption[]` array, the vendored `OmniFilter` from
   `@/libs/tigera/ui-components`, and `setFilter` from `useFlowLogsUrlFilters`
   for writes. `listType='radio'` for single-select, `'checkbox'` for
   multi-select; `showSearch={false}`.
   - The component MUST accept and use `filterId`, `filterLabel`, and
     `selectedFilters` as props even though it could read the URL itself: the
     vendored `OmniFilterList` inspects its direct children's props to decide
     chip visibility and Reset behaviour, and the handed-down label is the
     single source of truth.
   - Do not modify `src/libs/tigera/ui-components/` (vendored) — wrap it.
3. **`TableFilters/filters.ts`** — add the id to `tableLevelFilterIds` at its
   bar position and a label to `filterLabels`.
4. **`TableFilters/index.tsx`** — hand-place the component in the JSX at the
   position matching its `tableLevelFilterIds` slot, passing
   `filterId={FilterKeys.my_filter}`, `filterLabel={filterLabels.my_filter}`,
   and the selection mapped from `selectedValues`.

## Tests (same PR — no follow-ups)

The full map is in `whisker/DESIGN.md` §3. For a new filter:

- **`whisker/src/utils/filters/__tests__/filters.test.ts`** — always:
  - Add a row to the wire-format corpus in "URL -> flows filter query"
    (URL params in → exact `filters` blob out).
  - Update the registry-invariant tests — they enumerate the exact URL key
    set and the exact `dataFilters` set, so they fail until you extend them.
    That failure is the prompt to make a deliberate decision, not a nuisance.
- **Static filter** — component test modeled on
  `ReporterOmniFilter/__tests__/`: renders the fixed options, writes the URL
  on change, never fetches.
- **e2e** (`cd whisker && yarn e2e`, see `whisker/e2e/README.md`):
  - `e2e/tests/backend-contract.spec.ts` — a deep-link case pinning the exact
    blob the backend receives for the new param.
  - Visual baselines: adding a chip changes the bar. Regenerate both committed
    screenshot sets and commit them: `yarn e2e:snapshots` for your own
    platform (darwin-arm64 on a Mac) and `make -C whisker e2e-snapshots-ci`
    for the linux-x64 set CI compares against. Eyeball the diffs —
    `--update-snapshots` blesses regressions as happily as intended changes.

Run the jest suite with `cd whisker && yarn test` (or `yarn test:update` for
snapshots); `yarn verify` runs format + lint + coverage + build.

## Update the design doc

`whisker/DESIGN.md` records the URL key surface, the chip tree, and the
registry sets. Adding a filter changes all three — update the doc in the same
PR (repo rule; the doc's own "Keep this in sync" section says the same).

## Gotchas

- **Don't widen a registry.** One filter needing an extra knob is a new
  component or module, not an optional field on the shared spec type.
- **Bar order is pinned by screenshots.** Position in
  `tableLevelFilterIds`/`tableLevelDataFilterIds` is user-visible; expect
  visual-baseline churn and commit it.
- **`protocol` and `staged_action` are precedent** for URL params that are
  *not* chips of their own — they're written by the Port and Action chips via
  `setMultiFilter`. If your filter pairs with an existing chip, extend that
  chip rather than adding a bar entry.
- **Policy sub-selects don't narrow** (`narrowByActiveFilters: false`) —
  deliberate, user-visible behaviour. New data filters should keep the default
  (narrowed) unless there's a product decision to differ.
- **The `filters` blob is not URL-encoded on the stream path** — EventSource
  encodes the URL itself; double-encoding is a silent no-results bug.
- **Single-value quirks are intentional** where pinned by tests (e.g.
  `dest_port` dropping port `0` and non-numeric input). Match existing
  behaviour; changing it is a separate decision.
