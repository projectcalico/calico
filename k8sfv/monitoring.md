
# k8sfv test monitoring

There is a permanent Prometheus/Grafana setup that monitors results
and metrics from our nightly k8sfv CI runs.

This doc explains:

-   where to see that setup
-   how to interpret the results and metrics that it shows
-   technical details of how that setup runs
-   how to recreate that setup, if you need to.

## Where to see that setup

Grafana is at <http://10.248.1.7:3000> and Prometheus at
<http://10.248.1.6:9090>.  Those addresses are accessible from within
the `calico-test` GCE project, so use SSH forwarding to map onto some
local port number, for example

    gcloud compute ssh user@machine -- -4 -L 8082:10.248.1.7:3000

and then visit <http://localhost:8082> in your web browser.


## How to interpret the results and metrics that it shows

Each k8sfv test run reports a set of metrics when the run as a whole
completes.

-   **k8sfv_test_result:** Indicates whether each test case passed (1) or
    failed (0).  Hence `sum(k8sfv_test_result)` is the number of
    passing test cases.

-   **k8sfv_occupancy_mean_bytes:** Indicates the mean occupancy, in
    bytes, that was recorded during each test case.  (In principle;
    currently only the leak test actually provides this metric.)  The
    occupancy measure that we use is Golang's
    `go_memstats_heap_alloc_bytes`.

-   **k8sfv_occupancy_increase_percent:** Indicates the occupancy increase
    per cycle, as a percentage of the mean occupancy, in each test
    case that probes possibly memory leaking.  (Currently just the
    leak test.)

-   **k8sfv_heap_alloc_bytes:** Occupancy measurements at specific points
    during k8sfv test cases.

k8sfv puts the following labels on these metrics.

-   **code_level:** Indicates the line of development of the code used for
    that test, e.g. as `<repository name>-<branch>`.  So
    measurements with
    `https://github.com/projectcalico/felix.git-master`
    indicate checked-in Felix master code.  Tests with
    non-checked in code should have `dev` here.

-   **test_name:** The full Ginkgo test case name, such as "with a k8s
    clientset with 1 remote node should not leak memory".

-   **test_step:** For test cases that, e.g., record metrics at points
    within that test case, some name indicating the test
    step, such as "iteration2".


## Technical details of how that setup runs

The monitoring pieces - Grafana, a Prometheus server, and a Prometheus
push gateway - run in a GKE container cluster, "k8sfv", in the
`calico-test` GCE project.


## How to recreate that setup, if you need to

-   Create a GKE container cluster with 2 nodes.  Follow the web UI
    instructions to get credentials so you can run `kubectl` on your own
    machine, targetting that cluster.

-   Run `kubectl apply -f monitoring.yaml` repeatedly, with intervening
    pauses, until it completely succeeds (where `monitoring.yaml` is in
    the same place as the source of this doc).

    (The main delay needed, after the first time, is for the Prometheus
    Operator to get going and register the 'Prometheus' and
    'ServiceMonitor' TPRs.)

-   Use `kubectl get po` to check that pods are all running.

-   Use `kubectl get endpoints` to find the IP addresses for Grafana,
    the Prometheus server ("prometheus-operated") and the Prometheus
    push gateway ("prom-gateway").

-   Login to the Grafana web UI and configure the data source to the
    Prometheus server, with:

        {
            "name": "my-prom",
            "type": "prometheus",
            "url": "http://<Prometheus server IP>:9090",
            "access": "proxy",
            "isDefault": true,
            "user": "admin",
            "password": "admin"
        }

-   If you want your k8sfv test runs (or the nightly CI runs) to push
    metrics and results to this new setup, configure them to run with
    the `PROMPG_URL` environment variable set to `http://<Prometheus
      push gateway IP>:9091`.


## Outstanding queries

We don't set up an external IP for the push gateway.  Not sure if this
is OK; it depends if it will be sustainable for the k8sfv CI job to
reference the push gateway's endpoint IP directly (which is currently
10.248.1.4).  If not, then I think the longer term options are (1) to
set up an external IP, and do whatever is needed to secure it
appropriately, or (2) run parts of the k8sfv test - at least the k8sfv
test process itself - within the GKE cluster instead of on a GCE
instance.

We give a name 'metrics' to the push gateway's 9091 port.  It's
certainly the case that the ServiceMonitor's 'port' field needs to be
a string and not a number, but possibly it would work equally well to
use 'targetPort: 9091' instead.  So not sure if that is needed.
