# Whisker end-to-end tests

Browser-level tests that drive the real app against a stub whisker-backend.

They exist to survive refactoring. The jest suite under `src/` is thorough but
heavily mock-coupled — `src/pages/FlowLogsPage/__tests__/index.test.tsx` mocks 25
modules by import path, including every direct child component — so it asserts
today's module boundaries rather than user-visible behaviour. Move a boundary and
those tests get rewritten in the same commit as the change they were supposed to
protect. The specs here assert only what a user can see and what the backend
receives, so they keep their meaning across internal restructuring.

## Running

```bash
yarn e2e:install     # once: downloads the Chromium build Playwright pins
yarn e2e             # run everything
yarn e2e --headed    # watch it happen
yarn e2e:ui          # interactive runner, good for writing new specs
yarn e2e:report      # open the HTML report from the last CI-style run
```

Those run against your own platform's browser, which is what you want for the dev
loop. To reproduce CI exactly — same container, same architecture, same screenshot
baselines — use `make -C whisker e2e-ci` instead. See [In CI](#in-ci).

`yarn e2e` starts both servers itself (the stub on :8081 and `rsbuild dev` on
:3000) and reuses them if they are already up. Traces, screenshots and video are
captured on failure into `e2e-results/`; open one with:

```bash
yarn playwright show-trace e2e-results/<test-dir>/trace.zip
```

## Layout

| Path                             | What it is                                                             |
| -------------------------------- | ---------------------------------------------------------------------- |
| `stub/server.mjs`                | Programmable stand-in for whisker-backend. No fixture data of its own. |
| `support/stub.ts`                | Typed client for the stub's control API.                               |
| `support/test.ts`                | Playwright fixtures: stub reset, network isolation, shared locators.   |
| `fixtures/flows.ts`              | Flow log builders.                                                     |
| `tests/flow-logs.spec.ts`        | Table rendering, empty state, live append, row details.                |
| `tests/high-volume.spec.ts`      | Hundreds of flows: sort order, virtualisation, sustained streaming.    |
| `tests/stream-controls.spec.ts`  | Pause/resume, and the row-click pause.                                 |
| `tests/filters.spec.ts`          | Applying filters, deep links, reset.                                   |
| `tests/backend-contract.spec.ts` | What the frontend actually asks the backend for.                       |
| `tests/errors.spec.ts`           | Stream failure, recovery, degraded filter hints.                       |
| `tests/visual.spec.ts`           | Screenshot baselines. See below.                                       |
| `screenshot.css`                 | Hides dev-only chrome from every screenshot.                           |

## The stub backend

`stub/server.mjs` deliberately knows nothing about flow logs beyond their wire
framing (`data: <json>\n\n`, matching `lib/httpmachinery`'s
`eventStreamResponseWriter`). Each test pushes in exactly the payloads it wants:

```ts
await stub.setBacklog([aFlowLog({ source_name: 'nginx' })]); // sent on stream open
await gotoFlowLogs(page);
await stub.emit([aFlowLog({ source_name: 'later' })]); // pushed live
```

It also records every request the app makes, which is the part component tests
cannot reach:

```ts
await gotoFlowLogs(page, '?dest_port=8443&protocol=tcp');

expect(await stub.lastStreamFilters()).toEqual({
    dest_ports: [{ type: 'Exact', value: 8443 }],
    protocols: [{ type: 'Exact', value: 'tcp' }],
});
```

A wrong `filters` blob shows the user an empty table rather than an error, so
this is a regression that ships quietly. `stub.streams()` similarly exposes
open/opened/closed counts, which is how the specs assert that changing a filter
restarts the stream rather than silently reusing the old one.

## Notes and constraints

- **The API URL is baked in at build time.** `APP_API_URL` in `.env` points at
  `http://localhost:8081/whisker-backend`, so the stub has to listen on that port
  and prefix; it cannot be redirected at runtime. Override with `E2E_STUB_PORT`
  only if you change `.env` to match.
- **The stub sends CORS headers**, which the real whisker-backend does not. The
  app and the stub are on different origins in dev, so `EventSource` and `fetch`
  would otherwise be blocked. This is a stub-only concern.
- **Tests run serially** (`workers: 1`). The stub is one shared process that
  records requests, so overlapping tests would see each other's traffic.
- **Assertions wait longer than usual.** `useStream` buffers incoming flows for
  1s (`STREAM_THROTTLE`) before committing them to state, so `expect` timeouts
  are set to 15s rather than the default 5s.
- **The app is sealed off from the internet.** `support/test.ts` serves
  `/config.json` from a fixture with notifications disabled, and aborts any
  request to a non-local host. If a spec starts failing with a
  `blocked external request` warning, the app gained a new outbound call.
- **Keep fixture flow counts small** (under ~10) unless volume is the point. The
  table is virtualised with `react-window`, so off-screen rows are not in the DOM
  and locators will not find them.

## Testing at volume

`high-volume.spec.ts` is the exception to the note above: a busy cluster streams
flows continuously, and only volume exercises the throttled buffer in `useStream`
and the virtualised list. Build the flows with `manyFlowLogs(count)`, which names
them `flow-0000` upwards, oldest first, with strictly increasing timestamps so
the table's default `start_time` descending sort has one correct answer:

```ts
const flows = manyFlowLogs(250); // index 0 oldest, index 249 newest

await stub.setBacklog(flows); // or emit slices of it, in order, to stream
```

Generate one array and emit slices of it rather than calling `manyFlowLogs` per
batch — separate calls produce overlapping timestamp ranges, and the order
between batches stops being decidable.

Because rows below the fold are not in the DOM, `support/test.ts` adds:

- `renderedFlowNames(page)` — the flow names on screen, top row first. Assert
  ordering against this, and assert against its length to pin virtualisation.
- `scrollToFlowLogRow(page, name)` — wheels the list until that row mounts, which
  is how a test reaches the oldest flow at the bottom of a long list.

The 20,000 flow `BUFFER_LIMIT` in `src/api/index.ts` is deliberately not covered:
streaming enough flows to reach it costs minutes per run.

## Visual baselines

`visual.spec.ts` captures 15 screenshots of the states a user actually looks at.
Nothing else in this repo asserts anything about appearance: `src/theme` (~2.2k
lines) and the 550-odd CSS custom properties in `src/styles` are both excluded
from jest coverage, and every behavioural spec passes happily against a component
that works correctly and renders wrong. That gap matters while the app is
mid-migration from Chakra to Radix/shadcn/Tailwind, because most of these
components are going to be rebuilt.

```bash
yarn e2e                              # baselines checked like any other assertion
yarn e2e:snapshots                    # regenerate for your own platform
make -C whisker e2e-snapshots-ci      # regenerate the set CI compares against
```

**Review the diff image before accepting a regenerated baseline.** An unreviewed
`--update-snapshots` is the visual equivalent of `jest -u`: it will happily bless
a real regression. Failures write `-expected`, `-actual` and `-diff` PNGs into
`e2e-results/`, and the HTML report shows them side by side.

### Two committed sets, and why

Baselines live in `tests/__screenshots__/<platform>-<arch>/`, and **both committed
sets have to be updated together** when a visual change is intentional:

| Set            | Used by                            |
| -------------- | ---------------------------------- |
| `linux-x64`    | CI, via `make e2e-ci`              |
| `darwin-arm64` | `yarn e2e` on an Apple Silicon Mac |

Font rasterisation differs between macOS and the Linux container CI runs in, so
one set cannot serve both. The architecture is in the path because Playwright's
`{platform}` token is only `linux` — without it, an arm64 set generated on a
laptop would silently overwrite the amd64 set CI compares against, and the specs
would pass locally while proving nothing.

`e2e-snapshots-ci` therefore defaults to `--platform linux/amd64` even on an arm64
laptop. That runs emulated, so the suite takes roughly twice as long (~2min rather
than ~45s) — worth it, because it produces exactly the pixels CI will compare.
`E2E_PLATFORM=linux/arm64` runs native if you only want to iterate on behavioural
specs; the visual ones will fail there, since no arm64-linux set is committed.

If you would rather not run Docker locally at all, `make e2e-snapshots-ci` in CI
stages the regenerated set into `artifacts/whisker-e2e/`, so you can trigger it,
download the PNGs from the job and commit them.

What makes these stable:

- **Fixed timestamps.** `staticFlowLogs()` pins flows to a fixed instant, because
  everything else in `fixtures/flows.ts` is stamped "now" and the table renders
  times with `toLocaleTimeString()`. `locale` and `timezoneId` are pinned in the
  config for the same reason.
- **Frozen animations.** `animations: 'disabled'` settles Chakra's Skeleton pulse.
  `toHaveScreenshot` also retries until two consecutive captures agree, which
  covers the framer-motion row transitions that CSS freezing cannot stop.
- **Past timestamps.** `useShouldAnimate` only animates rows newer than the
  highest `start_time` seen so far, so dated fixtures skip the entry animation.
- **Element scope.** Most shots are scoped to the table, a popover or the details
  panel, so an unrelated layout change does not invalidate every baseline at once.
  Full-page shots are reserved for states that _are_ the whole page.

Note that `flow-logs-table` covers the table **body** only — `DataTable` renders
the column headers as a sibling. Use `flowLogsTableWithHeader(page)` when the
headers matter.

## Known defects pinned here

Specs marked `test.fail(...)` document real bugs: they pass while the bug exists
and start failing the moment it is fixed, so CI stays green without the defect
being forgotten.

- `flow-logs.spec.ts` — expanding a flow whose `policies.pending` is `null`
  crashes the page. whisker-backend's `PolicyTrace.Pending` has no `omitempty`
  and is a nil slice when there are no pending policies, so it serializes as
  `null`; `transformPolicyLog` in `PoliciesLogDetails` calls `.map` on it
  unguarded and the error boundary blanks the page.

There is a matching convention in the jest suite: `it.failing(...)` in
`src/utils/__tests__/omniFilter.test.ts` pins a crash on URLs carrying
`?pending_action=`.

## In CI

The suite runs as the **"Whisker: e2e"** job in the existing Whisker block, so it
inherits that block's `change_in` guard and only runs when whisker changes.

```yaml
- name: 'Whisker: e2e'
  commands:
      - ../.semaphore/run-and-monitor e2e.log make e2e-ci
```

`make e2e-ci` runs everything inside `mcr.microsoft.com/playwright:<pinned>-noble`,
which ships the browsers and system libraries already. It has to be that image
rather than the `node:22.15` one the other Whisker jobs use: installing Chromium
and its system dependencies is not possible as the non-root user
`DOCKER_RUN_RM` runs as. The job needs nothing from the agent but docker.

Details worth knowing if it misbehaves:

- **The image tag is derived from `package.json`**, not hardcoded. The image
  carries only the browser build matching its own Playwright version and refuses
  to launch against a mismatched one, so bumping `@playwright/test` moves the tag
  automatically.
- **`node_modules` lives in a named volume**, not the bind mount, so a laptop's
  darwin install is not clobbered by the container's linux one. It costs an extra
  `yarn install` per run.
- **The container runs as root** — the image's default, and the only way to write
  to a freshly created named volume — and chowns anything it leaves in the repo
  back to the caller before exiting.
- **Results are published.** `e2e-stage-artifacts` copies `e2e-results` (traces,
  videos, screenshot diffs), `e2e-report` and the baselines into
  `artifacts/whisker-e2e/`, which Semaphore's epilogue pushes as job artifacts. So
  a visual failure can be diagnosed from the diff PNGs without reproducing it.
- **The image pull is ~2GB** on a cold agent, which dominates the job's runtime.

Still worth re-checking on the first few real runs: `high-volume.spec.ts` paces
batches with fixed `waitForTimeout`s tuned to `STREAM_THROTTLE`. That is stable
locally (verified with `--repeat-each=3`, and again emulated under
`--platform linux/amd64`), but a loaded CI agent is a different environment. If it
proves flaky there, replace the fixed waits with polling on `stub.streams()`
rather than reaching for `retries`.
