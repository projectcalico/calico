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
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/winutils"
)

var ErrServiceNotReady = errors.New("missing Kubernetes service IP or port")

type Typha struct {
	Addr     string
	IP       string
	NodeName *string
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
	epClient := d.k8sClient.CoreV1().Endpoints(d.k8sNamespace)
	eps, err := epClient.Get(context.Background(), d.k8sServiceName, v1.GetOptions{})
	if err != nil {
		logrus.WithError(err).Error("Unable to get Typha service endpoints from Kubernetes.")
		return nil, err
	}

	var (
		candidates               int
		local, remote, addresses []Typha
	)

	for _, subset := range eps.Subsets {
		var portForOurVersion int32
		for _, port := range subset.Ports {
			if port.Name == d.k8sServicePortName {
				portForOurVersion = port.Port
				break
			}
		}

		if portForOurVersion == 0 {
			continue
		}

		// If we get here, this endpoint supports the typha port we're looking for.
		for _, h := range subset.Addresses {
			typhaAddr := net.JoinHostPort(h.IP, fmt.Sprint(portForOurVersion))
			if h.NodeName != nil && *h.NodeName == d.nodeName { // is local
				local = append(local, Typha{Addr: typhaAddr, IP: h.IP, NodeName: h.NodeName})
			} else {
				remote = append(remote, Typha{Addr: typhaAddr, IP: h.IP, NodeName: h.NodeName})
			}
			candidates++
		}
	}

	// return results with local endpoints first on the list
	if candidates == 0 {
		logrus.Error("Didn't find any ready Typha instances.")
		return nil, ErrServiceNotReady
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
