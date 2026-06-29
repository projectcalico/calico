# confd BIRD template testing

These tests verify that confd's BIRD template rendering produces the correct output for both the etcd and KDD (Kubernetes) backends.

Tests run in-process using envtest (KDD) and a standalone etcd process, with no Docker or external binaries required beyond the envtest assets.

To run: `make -C confd fv`

## Test Structure

- `helpers_test.go` — shared test infrastructure (backend setup, resource helpers, confd/Typha lifecycle)
- `*_test.go` — test files organized by feature (mesh, explicit peering, BGP filters, etc.)
- `mock_data/calicoctl/` — YAML input fixtures applied via the Calico client
- `compiled_templates/` — golden files for expected BIRD config output

## Mock Data

The mock data and compiled templates were originally generated in a cluster with three nodes:

- kube-master (10.192.0.2/16)
- kube-node-1 (10.192.0.3/16)
- kube-node-2 (10.192.0.4/16)

## Compiled Templates

Golden files live in `compiled_templates/`. For small changes, edit them by hand. For large template changes, run with `UPDATE_EXPECTED_DATA=true` to automatically overwrite the golden files with the actual rendered output:

```bash
make -C confd fv UPDATE_EXPECTED_DATA=true
```

When a test fails without this flag, the diff output shows the expected vs actual content and the paths to both files on disk.
