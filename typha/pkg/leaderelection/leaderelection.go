// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

// Package leaderelection wraps client-go's Lease-based leader election to give
// Typha a continuously-running elector that:
//
//   - Re-enters the election automatically after losing leadership (instead of
//     exiting like RunOrDie does).
//   - Exposes role transitions on a buffered channel so consumers (WS-C) can
//     react without coupling directly to the client-go callbacks.
//   - Releases the lease on context cancellation (ReleaseOnCancel) so rolling
//     restarts hand over leadership quickly.
//
// IMPORTANT: client-go's leaderelection package provides *best-effort*
// single-leader semantics.  Clock skew or API server partitions can cause two
// replicas to both believe they are leader for a window up to LeaseDuration.
// WS-C must tolerate dual-leader — two Typhas running real syncers briefly is
// safe (both serve correct data; transient extra datastore load).
// See typha/DESIGN.md §"Leader election" for the full discussion.
package leaderelection

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	"github.com/projectcalico/calico/typha/pkg/promutils"
)

// Role represents whether this Typha instance currently holds the leader lease.
type Role int

const (
	// Follower means this instance does not currently hold the lease.
	Follower Role = iota
	// Leader means this instance currently holds the lease.
	Leader
)

func (r Role) String() string {
	switch r {
	case Leader:
		return "Leader"
	default:
		return "Follower"
	}
}

// Config holds the configuration for the Elector.  Defaults match the
// client-go recommended ratios (LeaseDuration 15s, RenewDeadline 10s,
// RetryPeriod 2s) which satisfy the constraints:
//
//	LeaseDuration > RenewDeadline > RetryPeriod * JitterFactor (1.2)
type Config struct {
	// Enabled gates all election machinery.  When false, New returns nil and
	// Start is a no-op.
	Enabled bool

	// LeaseName is the name of the coordination.k8s.io/v1 Lease object.
	// Defaults to "calico-typha-leader".
	LeaseName string

	// LeaseNamespace is the namespace in which the Lease object lives.
	// Defaults to the pod's own namespace (PodNamespace).
	LeaseNamespace string

	// Identity uniquely identifies this candidate.  Must be non-empty and
	// stable across restarts (pod names satisfy this).  Defaults to PodName.
	Identity string

	LeaseDuration time.Duration // default 15s
	RenewDeadline time.Duration // default 10s
	RetryPeriod   time.Duration // default 2s
}

func (c *Config) applyDefaults(podName, podNamespace string) {
	if c.LeaseName == "" {
		c.LeaseName = "calico-typha-leader"
	}
	if c.LeaseNamespace == "" {
		c.LeaseNamespace = podNamespace
	}
	if c.Identity == "" {
		c.Identity = podName
	}
	if c.LeaseDuration == 0 {
		c.LeaseDuration = 15 * time.Second
	}
	if c.RenewDeadline == 0 {
		c.RenewDeadline = 10 * time.Second
	}
	if c.RetryPeriod == 0 {
		c.RetryPeriod = 2 * time.Second
	}
}

// Prometheus metrics registered at package init time so they are always
// present even if election is disabled (consistent with how other typha
// metrics work).
var (
	gaugeLeader = promutils.GetOrRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "typha_leader",
		Help: "1 if this Typha instance is currently the leader, 0 otherwise.",
	}))

	counterTransitions = promutils.GetOrRegister(prometheus.NewCounter(prometheus.CounterOpts{
		Name: "typha_leader_transitions_total",
		Help: "Total number of times this Typha instance has transitioned between Leader and Follower roles.",
	}))

	gaugeHolderInfo = promutils.GetOrRegister(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_leader_holder_info",
		Help: "Info-style gauge carrying the identity of the current lease holder (value always 1).",
	}, []string{"holder"}))
)

// Elector wraps client-go leader election so that:
//   - The election reruns automatically after leadership is lost.
//   - Role transitions are published on a buffered channel.
//   - The lease is released on context cancellation.
//
// Each Elector is bound to a single Lease (LeaseName + LeaseNamespace), so
// multiple Elector instances can run in parallel for different leases — the
// WS-E tier-1 election uses this.
type Elector struct {
	cfg       Config
	clientset kubernetes.Interface

	// roles receives a Role each time leadership is acquired or lost.
	// Buffered so that a single fast acquire+lose cycle does not block the
	// Run goroutine.
	roles chan Role

	mu     sync.RWMutex
	holder string // last observed holder identity, "" until first observation
}

// New constructs an Elector.  podName and podNamespace are used to fill in
// Config defaults (Identity and LeaseNamespace respectively).
//
// Returns nil if cfg.Enabled is false; callers must nil-check.
func New(cs kubernetes.Interface, cfg Config, podName, podNamespace string) *Elector {
	if !cfg.Enabled {
		return nil
	}
	cfg.applyDefaults(podName, podNamespace)
	return &Elector{
		cfg:       cfg,
		clientset: cs,
		roles:     make(chan Role, 16),
	}
}

// Roles returns the channel on which role transitions are published.
// Each send is edge-triggered: consumers receive Leader when this instance
// acquires the lease and Follower when it loses it.  The channel is never
// closed; consumers should stop reading when their own context is done.
//
// The initial role (before the first election completes) is implicitly
// Follower; the channel only delivers transitions.
func (e *Elector) Roles() <-chan Role {
	return e.roles
}

// CurrentHolder returns the identity of the last observed lease holder and
// whether a holder has been observed yet.  WS-C uses this to locate the
// leader's pod for upstream connection setup.
func (e *Elector) CurrentHolder() (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.holder == "" {
		return "", false
	}
	return e.holder, true
}

// Run starts the election loop and blocks until ctx is cancelled.
//
// Run must be called exactly once, typically in a goroutine.  On context
// cancellation it releases the lease (ReleaseOnCancel) and returns.
func (e *Elector) Run(ctx context.Context) {
	log.WithFields(log.Fields{
		"leaseName":      e.cfg.LeaseName,
		"leaseNamespace": e.cfg.LeaseNamespace,
		"identity":       e.cfg.Identity,
	}).Info("Leader election starting")

	for {
		if ctx.Err() != nil {
			log.Info("Leader election context cancelled, stopping")
			return
		}
		e.runOnce(ctx)

		// runOnce emits Follower internally (via OnStoppedLeading) when
		// leadership is lost.  Re-enter the election unless cancelled.
		if ctx.Err() != nil {
			return
		}
	}
}

// runOnce runs a single acquire→lead→lose cycle.  It returns when leadership
// is lost or ctx is cancelled.
func (e *Elector) runOnce(ctx context.Context) {
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      e.cfg.LeaseName,
			Namespace: e.cfg.LeaseNamespace,
		},
		Client: e.clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: e.cfg.Identity,
		},
	}

	// wasLeader tracks whether OnStartedLeading was called in this runOnce
	// cycle.  client-go guarantees OnStoppedLeading is always called when
	// Run() exits — even if we never acquired the lease — so we must only emit
	// Follower when we actually held leadership.
	//
	// OnStartedLeading and OnStoppedLeading run in different goroutines
	// (OnStartedLeading is go-launched by client-go; OnStoppedLeading is a
	// deferred call on the Run goroutine), so we use an atomic for the flag.
	var wasLeader atomic.Bool

	lec := leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   e.cfg.LeaseDuration,
		RenewDeadline:   e.cfg.RenewDeadline,
		RetryPeriod:     e.cfg.RetryPeriod,
		ReleaseOnCancel: true,
		Name:            e.cfg.LeaseName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				wasLeader.Store(true)
				log.WithField("identity", e.cfg.Identity).Info("This Typha instance became leader")
				gaugeLeader.Set(1)
				counterTransitions.Inc()
				e.publish(Leader)
				// Block until we are cancelled; client-go will call
				// OnStoppedLeading when renew fails.
				<-ctx.Done()
			},
			OnStoppedLeading: func() {
				if wasLeader.Load() {
					log.WithField("identity", e.cfg.Identity).Info("This Typha instance lost leadership")
					gaugeLeader.Set(0)
					counterTransitions.Inc()
					e.publish(Follower)
				} else {
					log.WithField("identity", e.cfg.Identity).Debug("Leader election cycle ended without acquiring lease")
				}
			},
			OnNewLeader: func(identity string) {
				log.WithField("holder", identity).Info("Leader election: new leader observed")
				e.mu.Lock()
				e.holder = identity
				e.mu.Unlock()

				// Update info gauge: clear old label set and set the new one.
				gaugeHolderInfo.Reset()
				gaugeHolderInfo.WithLabelValues(identity).Set(1)
			},
		},
	}

	le, err := leaderelection.NewLeaderElector(lec)
	if err != nil {
		log.WithError(err).Error("Failed to create LeaderElector; will retry")
		// Brief back-off before re-trying to avoid a tight error loop.
		select {
		case <-ctx.Done():
		case <-time.After(e.cfg.RetryPeriod):
		}
		return
	}
	le.Run(ctx)
}

// publish sends a role on the roles channel.  If the channel is full (slow
// consumer) the oldest pending value is dropped to make room.  This prevents
// a blocked consumer from stalling the election loop.
func (e *Elector) publish(r Role) {
	select {
	case e.roles <- r:
	default:
		// Channel full — drop the oldest value and replace.
		select {
		case <-e.roles:
		default:
		}
		e.roles <- r
	}
}
