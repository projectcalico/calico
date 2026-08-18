# Test sets

Generated. Run `make -C e2e gen-test-set` and commit the result; CI fails the diff otherwise.

`index.txt` lists every CI lane in `.argoci/cron/`, `.semaphore/end-to-end/pipelines/` and `.semaphore/semaphore.yml.d/blocks/`, the test set it resolves to, and how many specs that set selects. `sets/` holds one file per distinct selection, listing the spec names a run would execute.

The point is review. A change to a config under `e2e/config/`, to a `K8S_E2E_FLAGS` regex, or to a spec's name or labels shows up here as the specs it added or removed, so the effect on CI coverage is visible in the PR rather than in the next cron run.

Set names come from the selection, not the lane:

- a lane on `E2E_TEST_CONFIG` is named after its config path, so `e2e/config/vpp/eks-vpp-encap-extnode-aws.yaml` becomes `sets/vpp/eks-vpp-encap-extnode-aws.txt`
- a lane still selecting by regex gets a `legacy/` name under its `FUNCTIONAL_AREA`, which disappears when the lane converts to a config
- lanes sharing a selection share one set, including counterpart lanes in the two CI systems, and a name that resolves to two different selections is an error

Most jobs in the PR pipeline's blocks build or unit test something rather than run the suite, so one counts as a lane only when it declares a `TEST_TYPE` or runs a kind e2e make target. Those jobs declare `E2E_TEST_CONFIG` in the job env, which is the only place the generator reads a selection from; a kind job that declares none is an error rather than a lane that quietly disappears from the index.

A job that runs the suite more than once resolves to one lane per run. The flannel migration script is the only one today: it runs a single connectivity spec before migrating, recorded as a `[pre-migration]` lane, then the whole suite with the job's own selection.

An empty set is a lane running no specs at all. The generator prints `EMPTY` for those rather than failing, since most are focused on WireGuard specs that only exist in the Enterprise suite.
