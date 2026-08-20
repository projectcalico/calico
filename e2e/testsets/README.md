# Test sets

Generated. Run `make -C e2e gen-test-set` and commit the result; CI fails the diff otherwise.

`index.txt` lists every CI lane in `.argoci/cron/` and `.semaphore/end-to-end/pipelines/`, the test set it resolves to, and how many specs that set selects. `sets/` holds one file per distinct selection, listing the spec names a run would execute.

The point is review. A change to a config under `e2e/config/`, or to a spec's name or labels, shows up here as the specs it added or removed, so the effect on CI coverage is visible in the PR rather than in the next cron run.

Set names come from the config, not the lane. `e2e/config/vpp/eks-vpp-encap-extnode-aws.yaml` becomes `sets/vpp/eks-vpp-encap-extnode-aws.txt`, and lanes sharing a config share one set, including counterpart lanes in the two CI systems.

A job that runs the suite more than once resolves to one lane per run. The flannel migration script is the only one today: it runs a single connectivity spec before migrating, recorded as a `[pre-migration]` lane, then the whole suite with the job's own config.

An empty set is a lane running no specs at all. The generator prints `EMPTY` rather than failing, but a config that selects nothing is a bug worth chasing.
