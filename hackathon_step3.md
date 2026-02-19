# Step 3: Status Output and Observability Enhancements

In this step, we add a new `status` subcommand to calicoctl that reports Calico cluster status and configurations in a terminal-friendly format. The command fetches cluster resources via Calico's internal libraries and presents a structured overview of networking, security, and observability settings—including Goldmane and Whisker status in the Observability section.

---

## The Idea

Users often need a quick snapshot of their Calico cluster: dataplane type, BGP mesh, overlay configuration, and observability components. Rather than querying multiple resources manually, `calicoctl status` aggregates this information into a single, readable report. The output uses tablewriter for clean tables and plain text headers, making it easy to scan in a terminal. We also add an eBPF suggestion when the dataplane is iptables or nftables, and surface BPFProfiling and Goldmane/Whisker status in the Observability section.

---

## How We Achieved It

1. **Registered the status command** in `calicoctl.go`—added it to the usage doc and the command switch.

2. **Created `commands/status.go`** with:
   - Docopt parsing for `--config` and `--allow-version-mismatch`
   - Version mismatch check via `common.CheckVersionMismatch`
   - Client creation via `clientmgr.GetClients` (Calico + Kubernetes clients)
   - Graceful fetching of ClusterInformation, FelixConfiguration, IPPools, BGPConfiguration, IPAMConfiguration
   - Goldmane and Whisker deployment detection by iterating Calico/Tigera namespaces and matching deployment names or `k8s-app` labels

3. **Inference helpers** for:
   - `dataplaneType`: eBPF if BPFEnabled, else nftables if IptablesBackend is NFT, else iptables
   - `overlayStatus`: from IPPools (VXLAN/IPIP modes) and FelixConfiguration
   - `bgpMeshEnabled`: from BGPConfiguration.NodeToNodeMeshEnabled (default true)
   - Goldmane/Whisker: "Running" if deployment has ready replicas, else "Not found" or "Not ready"

4. **Dataplane section** (pluggable, output varies by dataplane type):
   - **Common**: IPv6 support, Wireguard encryption
   - **iptables**: Iptables backend (Legacy/NFT/Auto), XDP acceleration, Generic XDP
   - **nftables**: NFTables mode, backend, XDP acceleration
   - **eBPF**: Connect-time LB, External service mode (Tunnel/DSR), BPF attach type (TC/TCX), RPF enforcement, Host conntrack bypass, XDP acceleration
   - **external**: External driver path, internal driver disabled

5. **Terminal-friendly output**:
   - Section headers with `===` underline
   - `tablewriter` tables for Dataplane, Networking, Observability, and Advanced Config
   - Plain text values: Enabled, Disabled, Running (no icons)

6. **eBPF suggestion**: After the Dataplane line, when dataplane is iptables or nftables, we print a note suggesting the Calico eBPF dataplane for better performance.

7. **Observability section** includes:
   - Goldmane status
   - Whisker status
   - Prometheus metrics (from FelixConfiguration)
   - eBPF Profiling (from FelixConfiguration.Spec.BPFProfiling)

---

## Gotchas

- **Pluggable dataplane**: Calico supports multiple dataplanes (iptables, nftables, eBPF, external). The Dataplane section shows different rows depending on which is in use. Fields like XDP acceleration apply to iptables/nftables; BPF-specific fields (Connect-time LB, External service mode) only appear for eBPF.

- **Kubernetes client may be nil**: When using an etcd backend (non-Kubernetes), `GetClients` returns `kubeClient == nil`. We handle this by showing "N/A (non-Kubernetes)" for Goldmane and Whisker.

- **Resource not found vs. error**: Use `cerrors.ErrorResourceDoesNotExist` to distinguish "resource does not exist" from real API errors. On not-found, we log and continue with nil/empty values.

- **IPAMConfiguration name**: The global config is named `"default"`; use `client.IPAMConfiguration().Get(ctx, "default", options.GetOptions{})`.

- **IptablesBackend enum**: The nftables value is `"NFT"` (not "nftables"); use `v3.IptablesBackendNFTables` for comparison.

---

## Adding Your Own Functionality

To extend the status report:

1. **Add a new section**: Create a new header block and table in `printStatus`. Follow the pattern of Networking or Observability.

2. **Fetch additional resources**: Add a fetch helper (e.g., `fetchWireguardConfiguration`) with graceful error handling. Call it from `Status` and pass the result to `printStatus`.

3. **Add rows to existing tables**: In the Observability section, append new rows with `t2.Append([]string{"Component", "Status", "Notes"})`.

4. **Detect more deployments**: Extend `fetchGoldmaneWhiskerStatus` to accept a list of deployment names or labels to look for, and return a map of component names to status.

---

## What's Next

Explore Calico's capabilities further at [docs.tigera.io](https://docs.tigera.io) to learn about eBPF dataplane, flow observability with Goldmane and Whisker, and advanced networking features.

---

**Continue the hackathon:**

- [Step 1: Extending Calico](hackathon-step1.md)
- [Step 2: Version Mismatch GitHub Lookup](hackathon-step2.md)
