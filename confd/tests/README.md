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

If changes are needed, and simple enough, the compiled templates can just be adjusted by hand. However if there were large changes to the templates, it would be better to spin up a new cluster, configure it, and pull the compiled templates from there so it can be verified that the new templates also work in a live cluster.

In a running `calico/node` you can find the compiled config files in `/etc/calico/confd/config/`.
