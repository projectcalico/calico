# confd BIRD template testing

These tests are aimed at testing the Calico BIRD templates against the
etcd and KDD backends.  They setup an etcd server and a Kubernetes API
server to populate with data from the `tests/mock_data` directory.

To run these tests simply execute `make test` from the confd root directory.
Alternatively run `make test-kdd` or `make test-etcd` to only run their respective
tests.

The tests will report any difference between the generated templates and the compiled
templates, and will also log the output of confd into `tests/logs`.

## Mock Data

The mock data, and compiled templates, were generated in a cluster setup
with three nodes:

- kube-master (10.192.0.2/16)
- kube-node-1 (10.192.0.3/16)
- kube-node-2 (10.192.0.4/16)

The cluster is spun up and Calico deployed as the CNI provider, doing additional
configuration as necessary (e.g. explicit peering) with `calicoctl`.

The mock data is split into 3 input formats:
-  etcd contains etcdv3 data to configure using etcdctl.  This is done just before the tests
   and is used to configure allocation blocks that cannot be configured through calicoctl.
-  kdd contains kubectl manifests used to configure the k8s nodes.  This is done just before
   the tests and is required because kdd nodes cannot be configured through calicoctl.
-  calicoctl contains most of the test data in calicoctl manifests.  The same data is shared
   by both the etcdv3 and kdd tests.

## Compiled Templates

Similar to above, the compiled templates were pulled from a working cluster matching
the configuration described by the `mock_data` directory structure.  It should be noted
that there is no difference in compiled templates between etcd and KDD.

If changes are needed, and simple enough, the compiled templates can just be adjusted
by hand.  However if there were large changes to the templates, it would be better
to spin up a new cluster, configure it, and pull the compiled templates from there
so it can be verified that the new templates also work in a live cluster.

In a running `calico/node` you can find the compiled config files in `/etc/calico/confd/config/`.
If you are using Kubernetes, you can use `kubectl` to pull out the files:

```
# Cluster is running node-mesh with IPIP set to off
kubectl cp kube-system/calico-node-xxxxx:/etc/calico/confd/config/ $REPO/tests/compiled_templates/mesh/ipip-off/
rm $REPO/tests/mesh/ipip-off/.*
```

Note that this will pull in the staging files that we keep in `calico/node` which
the `rm` statement deletes.
