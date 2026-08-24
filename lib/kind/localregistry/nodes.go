// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package localregistry

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
)

// ContainerdConfigPatches returns the containerd config kind must apply at
// cluster-creation time to enable per-host registry configuration. Pass the
// result as kind.Config.ContainerdConfigPatches. After the cluster is up,
// call ConfigureNodes to drop the per-upstream hosts.toml files in.
//
// containerd 2.x (kindest/node images from kind v0.27+) dropped the legacy
// inline registry.mirrors stanza in favour of this config_path + hosts.toml
// split. This format works for older nodes too, so it's the safe default.
func (f *Registry) ContainerdConfigPatches() []string {
	return []string{
		`[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"`,
	}
}

// ConfigureNodes points each named upstream at the facade by writing a
// hosts.toml into every kind node. Call it after kind.Up has created the
// nodes. Each upstream (e.g. "quay.io", "docker.io", "gcr.io") gets a
// /etc/containerd/certs.d/<upstream>/hosts.toml whose single mirror entry is
// the facade, reached over the kind network gateway.
//
// The mirror is given both "pull" and "resolve" capabilities. "resolve" is
// what lets an override win: containerd resolves the tag→digest through the
// facade (which returns the override's digest) instead of cross-checking the
// canonical upstream. Without "resolve" an override by tag would be defeated
// by imagePullPolicy: Always.
func (f *Registry) ConfigureNodes(ctx context.Context, kindNodes []nodes.Node, upstreams ...string) error {
	endpoint, err := f.nodeReachableURL(ctx)
	if err != nil {
		return err
	}
	// response_header_timeout / request_timeout / dial_timeout are the
	// per-host HTTP timeouts containerd applies to the fetcher talking
	// to this mirror. Defaults are aggressive (seconds). ensureManifest
	// / ensureBlob keep any single facade request bounded (manifests
	// are KB, blobs are one layer), so on the fast path these limits
	// never come near firing. They're a safety net for the streaming
	// blob case on slow upstreams — a large single layer over a slow
	// link can still take longer than containerd's default response
	// header timeout, so we bump it here rather than have containerd
	// give up mid-transfer. Warm-cache pulls stay ms-fast — the facade
	// responds immediately once the manifest / blob is in the internal
	// store. Supported by containerd 2.x, which is what kindest/node
	// images from kind v0.27+ ship.
	hostsTOML := fmt.Sprintf(`[host.%q]
  capabilities = ["pull", "resolve"]
  dial_timeout = "30s"
  response_header_timeout = "15m"
  request_timeout = "30m"
`, endpoint)

	for _, n := range kindNodes {
		for _, up := range upstreams {
			dir := "/etc/containerd/certs.d/" + up
			if err := n.Command("mkdir", "-p", dir).Run(); err != nil {
				return fmt.Errorf("mkdir %s on %s: %w", dir, n, err)
			}
			if err := nodeutils.WriteFile(n, dir+"/hosts.toml", hostsTOML); err != nil {
				return fmt.Errorf("write hosts.toml in %s on %s: %w", dir, n, err)
			}
		}
	}
	f.log.Info("configured node mirrors",
		"nodes", len(kindNodes),
		"upstreams", upstreams,
		"endpoint", endpoint,
	)
	return nil
}

// nodeReachableURL is the facade URL a kind node can dial: the kind docker
// network's gateway address (which routes to the host, where the facade
// listens) on the facade port. Plaintext http — the http:// scheme in the
// hosts.toml host key is what tells containerd not to require TLS.
func (f *Registry) nodeReachableURL(ctx context.Context) (string, error) {
	gw, err := f.dockerGatewayIP(ctx, f.cfg.KindNetwork)
	if err != nil {
		return "", err
	}
	// Use the actually-bound port, which differs from cfg.Port when the OS
	// assigned one (cfg.Port == 0).
	_, port, err := net.SplitHostPort(f.publicAddr)
	if err != nil {
		return "", fmt.Errorf("parse facade addr %q: %w", f.publicAddr, err)
	}
	return fmt.Sprintf("http://%s:%s", gw, port), nil
}

// dockerGatewayIP returns the IPv4 gateway of a docker network.
func (f *Registry) dockerGatewayIP(ctx context.Context, network string) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "network", "inspect", network,
		"-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker network inspect %s: %s: %w", network, strings.TrimSpace(string(out)), err)
	}
	for _, gw := range strings.Fields(string(out)) {
		if strings.Contains(gw, ".") { // first IPv4
			return gw, nil
		}
	}
	return "", fmt.Errorf("no IPv4 gateway found for docker network %q", network)
}
