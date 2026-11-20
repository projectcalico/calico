# Test sets

Generated. Run `make -C e2e gen-test-set` and commit the result; CI fails the diff otherwise.

`index.txt` lists every CI lane in `.argoci/cron/`, `.argoci/modules/` and `.semaphore/semaphore.yml.d/blocks/`, the test set it resolves to, and how many specs that set selects. `sets/` holds two files per lane. `<lane>.txt` lists the spec names a run would execute. `<lane>.drops.txt` lists every spec a suite of the lane selected that the lane drops, one per line, as the spec name, a tab, and the reason.

The point is review. A change to a config under `e2e/config/`, or to a spec's name or labels, shows up here as the specs it added or removed, so the effect on CI coverage is visible in the PR rather than in the next cron run.

Set names come from the lane, not its config: the CI system, the file that declares the lane, and the lane name in lowercase with hyphens. The `datastore-k8s-e2e-kdd-old [stable-1-canal-yaml]` cell in `.argoci/cron/e2e-iptables.yaml` becomes `sets/cron/e2e-iptables/datastore-k8s-e2e-kdd-old-stable-1-canal-yaml.txt`. Every matrix entry is its own lane, suffixed with the entry name even when it selects like its siblings, and lanes sharing a config each get their own file. Changing which configs a lane lists then shows up as a change to that lane's specs rather than as a renamed file.

A job that runs the suite more than once resolves to one lane per run. The flannel migration script is the only one today: it runs a single connectivity spec before migrating, recorded as a `[pre-migration]` lane, then the whole suite with the job's own config.

An empty set is a lane running no specs at all. The generator prints `EMPTY` rather than failing, but a config that selects nothing is a bug worth chasing.

A drop reason starts with its category. `Requires:BGP not provided` means the lane declares `provides:` and lacks that capability. `upstream: <group>` is an `upstream:` entry. `label <Label>: <reason>` and `excluded: <reason>` are the existing `exclude.labels` and `exclude.namePatterns` entries. `quarantine: CORE-13670` is a name-pattern entry carrying a `ticket:`, with the key taken from the ticket URL. A spec several rules drop is listed once, under the first of those categories in the order given, so a quarantine never hides a capability gap and adding or lifting one changes nothing else in the file.

To see why a lane runs or drops a spec without regenerating anything, run `make -C e2e explain-lane LANE=<set name> SPEC=<text>`. `SPEC` is optional and matches any part of a spec name, ignoring case. Without it the target prints every drop for the lane, grouped by reason.
