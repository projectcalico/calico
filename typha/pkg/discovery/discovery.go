// Copyright (c) 2020 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package discovery

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	discoveryv1 "k8s.io/api/discovery/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

var ErrServiceNotReady = errors.New("missing Kubernetes service IP or port")

// Tier classifies a discovered Typha endpoint within the hierarchical
// deployment.  Clients use it to apply the connection-preference policy (WS-E):
// same-node Typhas are always preferred whatever their tier; off-node clients
// may only use tier-2 Typhas when tiering is active.
type Tier int

const (
	// TierUnknown means the endpoint's tier could not be determined (label or
	// Service lag).  Treated as TierTwo to fail open — a brand-new cluster has no
	// tier labels yet and clients must still be able to connect.
	TierUnknown Tier = iota
	// TierTwo is a leaf Typha that serves ordinary clients.
	TierTwo
	// TierOne is a fan-out Typha that connects to the leader and serves tier-2.
	TierOne
	// TierLeader is the datastore-watching leader.
	TierLeader
)

func (t Tier) String() string {
	switch t {
	case TierLeader:
		return "leader"
	case TierOne:
		return "tier1"
	case TierTwo:
		return "tier2"
	default:
		return "unknown"
	}
}

type Typha struct {
	Addr     string
	IP       string
	NodeName *string
	// Tier is the endpoint's hierarchical tier, set only when tier-service
	// classification is enabled (WithTierServices).  TierUnknown otherwise.
	Tier Tier
}

type addrDedupeKey string

func (t Typha) dedupeKey() addrDedupeKey {
	node := "<nil>"
	if t.NodeName != nil {
		node = *t.NodeName
	}
	return addrDedupeKey(fmt.Sprintf("%s/%s/%s", t.Addr, t.IP, node))
}

func (t Typha) String() string {
	nodePart := ""
	if t.NodeName != nil {
		nodePart = "/" + *t.NodeName
	}
	if strings.Contains(t.Addr, t.IP) {
		// Mainline: IP included in address; avoid printing it twice.
		return t.Addr + nodePart
	}
	return t.Addr + "," + t.IP + nodePart
}

type Discoverer struct {
	addrOverrides      []string
	nodeName           string
	k8sClient          kubernetes.Interface
	k8sServiceName     string
	k8sNamespace       string
	k8sServicePortName string
	inCluster          bool
	filters            []func(typhaAddresses []Typha) ([]Typha, error)

	// Tier classification (WS-E).  When tierServicesEnabled is true, the
	// discoverer cross-references the leader and tier-1 Services' endpoints
	// against the main Service's endpoints to classify each Typha's tier, then
	// applies the client connection-preference policy.
	tierServicesEnabled bool
	leaderServiceName   string
	tier1ServiceName    string

	allKnownAddrs []Typha
}

type Option func(opts *Discoverer)

func WithAddrOverride(addr string) Option {
	return func(d *Discoverer) {
		if addr == "" {
			return
		}
		d.addrOverrides = []string{addr}
	}
}

func WithAddrsOverride(addrs []string) Option {
	return func(d *Discoverer) {
		d.addrOverrides = addrs
	}
}

func WithKubeClient(client kubernetes.Interface) Option {
	return func(d *Discoverer) {
		d.k8sClient = client
	}
}

// WithInClusterKubeClient enables auto-connection to Kubernetes using the in-cluster client config.
// this is disabled by default to avoid creating an extra Kubernetes client that is then discarded.
func WithInClusterKubeClient() Option {
	return func(d *Discoverer) {
		d.inCluster = true
	}
}

func WithKubeService(namespaceName, serviceName string) Option {
	return func(d *Discoverer) {
		d.k8sNamespace = namespaceName
		d.k8sServiceName = serviceName
	}
}

func WithKubeServicePortNameOverride(portName string) Option {
	return func(d *Discoverer) {
		d.k8sServicePortName = portName
	}
}

// WithNodeAffinity help discovery preference by supplying nodeName to determine which endpoints are local to node
func WithNodeAffinity(nodeName string) Option {
	return func(d *Discoverer) {
		d.nodeName = nodeName
	}
}

// WithTierServices enables hierarchical tier classification (WS-E).  The
// discoverer additionally lists the leader and tier-1 Services' endpoints (in
// the same namespace as the main Service) and classifies each discovered Typha's
// tier by cross-referencing IPs.  It then applies the client connection-
// preference policy:
//
//   - Same-node Typhas are always preferred, whatever their tier (including the
//     leader) — this smooths bootstrap.
//   - When tiering is active (the tier-1 Service has at least one endpoint),
//     off-node clients may only use tier-2 (or unknown-tier, fail-open) Typhas;
//     the leader and tier-1 are filtered out for off-node clients.
//   - When tiering is not active (single-tier / small clusters), off-node
//     clients may use any Typha.
//
// Pass empty service names to leave classification disabled.
func WithTierServices(leaderServiceName, tier1ServiceName string) Option {
	return func(d *Discoverer) {
		if leaderServiceName == "" && tier1ServiceName == "" {
			return
		}
		d.tierServicesEnabled = true
		d.leaderServiceName = leaderServiceName
		d.tier1ServiceName = tier1ServiceName
	}
}

func WithPostDiscoveryFilter(f func(typhaAddresses []Typha) ([]Typha, error)) Option {
	return func(d *Discoverer) {
		d.AddPostDiscoveryFilter(f)
	}
}

func New(opts ...Option) *Discoverer {
	d := &Discoverer{
		k8sServicePortName: "calico-typha",
	}

	for _, o := range opts {
		o(d)
	}

	return d
}

func (d *Discoverer) AddPostDiscoveryFilter(f func(typhaAddresses []Typha) ([]Typha, error)) {
	d.filters = append(d.filters, f)
}

// LoadTyphaAddrs tries to discover the best address(es) to use to connect to Typha.
//
// If an AddrOverride is supplied then that takes precedence, otherwise, LoadTyphaAddrs will
// try to lookup one of the backend endpoints of the typha service (using the K8sServiceName and
// K8sNamespace fields).
//
// Returns nil if typha is not enabled (i.e. fields are empty). If typha is enabled, this will return a non-empty slice
// or an error.
func (d *Discoverer) LoadTyphaAddrs() (ts []Typha, err error) {
	defer func() {
		d.allKnownAddrs = ts
	}()
	ts, err = d.discoverTyphaAddrs()
	if err != nil {
		return
	}
	for _, f := range d.filters {
		ts, err = f(ts)
		if err != nil {
			return nil, fmt.Errorf("typha post-discovery filter failed: %w", err)
		}
	}
	return
}

func (d *Discoverer) CachedTyphaAddrs() []Typha {
	return d.allKnownAddrs
}

func (d *Discoverer) TyphaEnabled() bool {
	return len(d.addrOverrides) > 0 || d.k8sServiceName != ""
}

func (d *Discoverer) discoverTyphaAddrs() ([]Typha, error) {
	if !d.TyphaEnabled() {
		return nil, nil
	}

	if len(d.addrOverrides) > 0 {
		// Explicit address; trumps other sources of config.
		var typhas []Typha
		for _, addr := range d.addrOverrides {
			typhas = append(typhas, Typha{Addr: addr})
		}
		return typhas, nil
	}

	// If we get here, we need to look up the Typha service using the k8s API.
	if d.k8sClient == nil && d.inCluster {
		// Client didn't provide a kube client but we're allowed to create one.
		logrus.Info("Creating Kubernetes client for Typha discovery...")
		k8sConf, err := winutils.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			logrus.WithError(err).Error("Unable to create in-cluster Kubernetes config.")
			return nil, err
		}
		d.k8sClient, err = kubernetes.NewForConfig(k8sConf)
		if err != nil {
			logrus.WithError(err).Error("Unable to create Kubernetes client set.")
			return nil, err
		}
	} else if d.k8sClient == nil {
		return nil, errors.New("failed to look up Typha, no Kubernetes client available")
	}

	// If we get here, we need to look up the Typha service endpoints using the k8s API.
	logrus.Info("(Re)discovering Typha endpoints using the Kubernetes API...")
	epClient := d.k8sClient.DiscoveryV1().EndpointSlices(d.k8sNamespace)
	endpointSlices, err := epClient.List(context.Background(), v1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, d.k8sServiceName),
	})
	if err != nil {
		logrus.WithError(err).Error("Unable to get Typha service endpoints from Kubernetes.")
		return nil, err
	}

	var (
		candidates               int
		local, remote, addresses []Typha
	)

	for i, eps := range endpointSlices.Items {
		var portForOurVersion int32
		for _, port := range eps.Ports {
			if *port.Name == d.k8sServicePortName {
				portForOurVersion = *port.Port
				break
			}
		}

		if portForOurVersion == 0 {
			if i != len(endpointSlices.Items)-1 {
				continue
			}
			logrus.Error("Didn't find any ready Typha instances.")
			return nil, ErrServiceNotReady
		}

		for _, endpoint := range eps.Endpoints {
			for _, addr := range endpoint.Addresses {
				if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
					continue
				}
				typhaAddr := net.JoinHostPort(addr, fmt.Sprint(portForOurVersion))
				if endpoint.NodeName != nil && *endpoint.NodeName == d.nodeName { // is local
					local = append(local, Typha{Addr: typhaAddr, IP: addr, NodeName: endpoint.NodeName})
				} else {
					remote = append(remote, Typha{Addr: typhaAddr, IP: addr, NodeName: endpoint.NodeName})
				}
				candidates++
			}
		}
	}

	// return results with local endpoints first on the list
	if candidates == 0 {
		logrus.Error("Didn't find any ready Typha instances.")
		return nil, ErrServiceNotReady
	}

	// Hierarchical tier classification + client preference policy (WS-E).  Only
	// active when tier Services are configured (Felix in hierarchical mode); a
	// no-op otherwise so the default deployment is unchanged.
	if d.tierServicesEnabled {
		local, remote = d.classifyAndApplyTierPolicy(local, remote)
		if len(local)+len(remote) == 0 {
			logrus.Error("All Typha endpoints filtered out by tier policy.")
			return nil, ErrServiceNotReady
		}
	}

	shuffleInPlace(local)
	shuffleInPlace(remote)

	addresses = append(local, remote...)

	fields := logrus.Fields{"addresses": addresses}
	if d.nodeName != "" {
		fields["local"] = local
		fields["remote"] = remote
	}

	logrus.WithFields(fields).Info("Found ready Typha addresses.")

	return addresses, nil
}

// classifyAndApplyTierPolicy sets the Tier field on the local and remote Typha
// lists (by cross-referencing the per-tier Services' endpoints) and applies the
// client connection-preference policy:
//
//   - Same-node (local) Typhas are always kept, whatever their tier.
//   - When tiering is active (the tier-1 Service has any endpoints), off-node
//     (remote) Typhas are filtered to tier-2 (and unknown, fail-open) only — the
//     leader and tier-1 are removed for off-node clients.
//   - When tiering is not active, off-node Typhas are kept whatever their tier.
//
// On any error listing the tier Services we fail open: leave everything as
// tier-unknown and keep all endpoints (the client must be able to connect).
func (d *Discoverer) classifyAndApplyTierPolicy(local, remote []Typha) (keptLocal, keptRemote []Typha) {
	leaderIPs := d.serviceEndpointIPs(d.leaderServiceName)
	tier1IPs := d.serviceEndpointIPs(d.tier1ServiceName)

	classify := func(ip string) Tier {
		if leaderIPs[ip] {
			return TierLeader
		}
		if tier1IPs[ip] {
			return TierOne
		}
		// Present in the main Service but not in a tier Service.  In an active
		// hierarchy that means tier-2; on a brand-new cluster (no labels yet) it
		// is genuinely unknown — either way we treat it as usable tier-2.
		return TierTwo
	}
	for i := range local {
		local[i].Tier = classify(local[i].IP)
	}
	for i := range remote {
		remote[i].Tier = classify(remote[i].IP)
	}

	// Tiering is "active" when the tier-1 Service has endpoints (equivalent to
	// Tier1Count>0 having taken effect).  We learn this from the client side
	// without needing Tier1Count plumbed to Felix.
	tieringActive := len(tier1IPs) > 0

	// Same-node endpoints are always kept whatever their tier.
	keptLocal = local

	if !tieringActive {
		// Single-tier / small cluster: off-node clients may use any Typha.
		keptRemote = remote
		return
	}

	// Tiering active: off-node clients may only use tier-2 (or unknown) Typhas.
	for _, t := range remote {
		if t.Tier == TierLeader || t.Tier == TierOne {
			logrus.WithFields(logrus.Fields{"addr": t.Addr, "tier": t.Tier}).Debug(
				"Filtering out off-node higher-tier Typha for leaf client.")
			continue
		}
		keptRemote = append(keptRemote, t)
	}
	return
}

// serviceEndpointIPs lists the ready endpoint IPs of the named Service (in the
// discoverer's namespace) as a set.  Returns an empty set on error or when the
// service name is empty — callers treat an empty set as "no endpoints" / fail
// open.
func (d *Discoverer) serviceEndpointIPs(serviceName string) map[string]bool {
	ips := map[string]bool{}
	if serviceName == "" || d.k8sClient == nil {
		return ips
	}
	epClient := d.k8sClient.DiscoveryV1().EndpointSlices(d.k8sNamespace)
	slices, err := epClient.List(context.Background(), v1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", discoveryv1.LabelServiceName, serviceName),
	})
	if err != nil {
		logrus.WithError(err).WithField("service", serviceName).Warn(
			"Failed to list tier Service endpoints; failing open (treating as no endpoints).")
		return ips
	}
	for _, eps := range slices.Items {
		for _, endpoint := range eps.Endpoints {
			if endpoint.Conditions.Ready != nil && !*endpoint.Conditions.Ready {
				continue
			}
			for _, addr := range endpoint.Addresses {
				ips[addr] = true
			}
		}
	}
	return ips
}

type AddressLoader interface {
	LoadTyphaAddrs() (ts []Typha, err error)
	CachedTyphaAddrs() []Typha
}

func NewConnAttemptTracker(d AddressLoader) *ConnectionAttemptTracker {
	cat := &ConnectionAttemptTracker{
		discoverer:         d,
		triedAddrsLastSeen: map[addrDedupeKey]time.Time{},
	}
	return cat
}

// ConnectionAttemptTracker deals with the fact that the list of available Typha instances may change during
// a connection attempt.  Each call to NextAddr refreshes the list of available Typha addresses (if needed)
// and then returns the first entry in the list that has not been returned before.  If the list is static,
// NextAddr() will effectively just iterate through the static list.
type ConnectionAttemptTracker struct {
	discoverer AddressLoader
	triedCache bool

	// triedAddrsLastSeen has en entry for each Typha address that has been
	// tried.  We use presence of an entry to prevent trying the same address
	// multiple times before we've tried all available addresses.  The timestamp
	// is used to clean up stale entries; each time we choose an address, we
	// refresh the timestamp on all the addresses that still exist.  The map is
	// reset when we run out of addresses to try.
	triedAddrsLastSeen map[addrDedupeKey]time.Time
}

func (d *ConnectionAttemptTracker) NextAddr() (Typha, error) {
	allKnownAddrs, err := d.refreshAddrs()
	if err != nil {
		return Typha{}, err
	}

	return d.pickNextTypha(allKnownAddrs), nil
}

func (d *ConnectionAttemptTracker) refreshAddrs() ([]Typha, error) {
	if !d.triedCache {
		// Very first time, we expect the discoverer to have a cache of the
		// addresses it loaded at start-up.  Try that.
		d.triedCache = true
		allKnownAddrs := d.discoverer.CachedTyphaAddrs()
		if len(allKnownAddrs) > 0 {
			logrus.WithField("addrs", allKnownAddrs).Debug("Using cached typha addresses.")
			return allKnownAddrs, nil
		}
		logrus.Debug("Cache was empty.")
	}

	// Either cache was empty or this isn't the first time. Refresh the list.
	// this is important during upgrade so that we can't get unlucky and spend
	// a long time iterating through all the back-level typhas that are being
	// shut down.
	logrus.Debug("Reloading list of Typhas...")
	addrs, err := d.discoverer.LoadTyphaAddrs()
	if err != nil {
		return nil, fmt.Errorf("failed to reload list Typha addresses: %w", err)
	}
	logrus.WithField("addrs", addrs).Debug("New list of Typha instances")
	if len(addrs) == 0 {
		logrus.Panic("NextAddr() called but this cluster doesn't use Typha?")
	}
	return addrs, nil
}

func (d *ConnectionAttemptTracker) pickNextTypha(allKnownAddrs []Typha) (out Typha) {
	foundUnusedTypha := false

	// Defensive: make sure we don't leak if typha addresses are churning.
	d.refreshAndGCLastSeen(allKnownAddrs)

	for _, a := range allKnownAddrs {
		addrKey := a.dedupeKey()
		if _, ok := d.triedAddrsLastSeen[addrKey]; ok {
			logrus.WithField("key", addrKey).Debug("Already tried this Typha")
			continue
		}
		out = a
		foundUnusedTypha = true
		break
	}
	if !foundUnusedTypha {
		// We've tried them all, reset the tracking set so we'll loop again...
		logrus.Debug("No unused Typha address found. Resetting.")
		clear(d.triedAddrsLastSeen)
		// ...starting with the first in the list.
		out = allKnownAddrs[0]
	}
	logrus.WithField("addr", out).Debug("Next typha to try.")
	d.triedAddrsLastSeen[out.dedupeKey()] = time.Now()

	return
}

// refreshAndGCLastSeen updates the last-seen times for existing entries in
// d.triedAddrsLastSeen and cleans up entries that haven't been seen for a
// long time.
func (d *ConnectionAttemptTracker) refreshAndGCLastSeen(addrs []Typha) {
	for _, a := range addrs {
		addrKey := a.dedupeKey()
		if _, ok := d.triedAddrsLastSeen[addrKey]; ok {
			d.triedAddrsLastSeen[addrKey] = time.Now()
		}
	}
	for k, v := range d.triedAddrsLastSeen {
		if time.Since(v) > 5*time.Minute {
			logrus.WithField("addr", k).Debug("Removing stale typha address from last seen cache.")
			delete(d.triedAddrsLastSeen, k)
		}
	}
}

func shuffleInPlace(s []Typha) {
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}
