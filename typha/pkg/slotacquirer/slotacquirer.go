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

// Package slotacquirer implements the multi-slot lease acquirer with "lazy
// candidacy" that drives WS-E's two-tier Typha hierarchy.
//
// A Typha deployment in two-tier mode runs N+1 Kubernetes Leases:
//
//   - calico-typha-leader        — the single datastore-watching leader.
//   - calico-typha-tier1-0..N-1  — the N tier-1 fan-out slots (N = Tier1Count).
//
// Every Typha runs one Acquirer.  The Acquirer's job is to make this instance
// hold *at most one* slot and to converge the deployment so that *exactly one*
// instance holds each slot.  The role it reports follows from which slot (if
// any) it holds:
//
//	holds calico-typha-leader   -> Leader
//	holds a tier1 slot          -> Tier1
//	holds nothing               -> Tier2
//
// # Why "lazy" candidacy
//
// The naive approach — run one client-go Elector per lease, all the time — has
// every idle Typha campaigning on every lease forever.  client-go electors poll
// their lease every RetryPeriod (default 2s), so a deployment of P Typhas and
// S = N+1 slots generates roughly P×S/RetryPeriod lease GETs per second against
// the API server, even in steady state when all slots are filled and nobody can
// win anything.  At the 1M-node target (thousands of tier-2 Typhas) that is a
// self-inflicted DoS on the API server — exactly what the hierarchy exists to
// avoid.
//
// Lazy candidacy fixes this: an instance that holds no slot does NOT keep
// electors running.  Instead it runs a single cheap watch/poll loop that lists
// the leases at a slow cadence (WatchInterval) and only spins up a real Elector
// for a slot when that slot looks *acquirable* (no holder, or the holder's lease
// has expired).  As soon as it wins any slot it tears down every other elector
// and stops campaigning entirely; the held slot's elector keeps the lease
// renewed.  When it loses its slot it returns to the slow watch loop.
//
// Steady-state cost per idle Typha is therefore one LIST every WatchInterval
// (default 10s) instead of S renew-GETs every RetryPeriod — a ~Sx/5 reduction —
// and the cost only rises (campaign electors start) transiently when a slot
// actually frees up.  The acquirer UTs assert this by counting API calls.
package slotacquirer

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/typha/pkg/leaderelection"
	"github.com/projectcalico/calico/typha/pkg/promutils"
)

// Role is the role implied by which slot (if any) this instance holds.
type Role int

const (
	// Tier2 means we hold no slot: we are a leaf Typha sourcing from tier-1.
	Tier2 Role = iota
	// Tier1 means we hold one of the tier-1 slots: we source from the leader
	// and fan out to tier-2 Typhas.
	Tier1
	// Leader means we hold the leader slot: we run the real datastore syncers.
	Leader
)

func (r Role) String() string {
	switch r {
	case Leader:
		return "Leader"
	case Tier1:
		return "Tier1"
	default:
		return "Tier2"
	}
}

// LeaderSlotName is the conventional name of the leader Lease.  It matches the
// single-tier (WS-C) lease name so that Tier1Count=0 reproduces WS-C exactly.
const LeaderSlotName = "calico-typha-leader"

// Tier1SlotPrefix is the name prefix of the tier-1 Leases; the full name is
// Tier1SlotPrefix + index, e.g. "calico-typha-tier1-0".
const Tier1SlotPrefix = "calico-typha-tier1-"

// electorFactory constructs and returns a runnable elector bound to one lease.
// Defined as a field so unit tests can substitute a fake elector that does not
// talk to a (fake) API server, letting them drive acquisition deterministically.
type electorFactory func(leaseName string) slotElector

// slotElector is the subset of leaderelection.Elector the acquirer drives: run
// it on a context, and observe role transitions.  The real implementation is
// *leaderelection.Elector; tests provide a fake.
type slotElector interface {
	Run(ctx context.Context)
	Roles() <-chan leaderelection.Role
}

// Config configures an Acquirer.
type Config struct {
	// Tier1Count is the number of tier-1 slots (N).  Zero means single-tier
	// (WS-C) mode: only the leader slot exists and the acquirer behaves exactly
	// like a single Elector on the leader lease.
	Tier1Count int

	// LeaseNamespace is the namespace the Leases live in.
	LeaseNamespace string

	// Identity is this instance's election identity (its pod name).
	Identity string

	// Election timing, passed through to each per-slot Elector.  Zero values get
	// the leaderelection package defaults.
	LeaseDuration time.Duration
	RenewDeadline time.Duration
	RetryPeriod   time.Duration

	// WatchInterval is how often an instance holding no slot lists the leases to
	// look for an acquirable slot.  This is the steady-state API cost of an idle
	// candidate.  Defaults to 10s.
	WatchInterval time.Duration
}

func (c *Config) applyDefaults() {
	if c.WatchInterval <= 0 {
		c.WatchInterval = 10 * time.Second
	}
	if c.LeaseDuration <= 0 {
		c.LeaseDuration = 15 * time.Second
	}
	if c.RenewDeadline <= 0 {
		c.RenewDeadline = 10 * time.Second
	}
	if c.RetryPeriod <= 0 {
		c.RetryPeriod = 2 * time.Second
	}
}

// slotNames returns the ordered list of all slot lease names: leader first,
// then tier1-0..N-1.
func (c *Config) slotNames() []string {
	names := make([]string, 0, c.Tier1Count+1)
	names = append(names, LeaderSlotName)
	for i := 0; i < c.Tier1Count; i++ {
		names = append(names, tier1SlotName(i))
	}
	return names
}

func tier1SlotName(i int) string {
	return Tier1SlotPrefix + itoa(i)
}

// itoa avoids pulling strconv into the hot slot-name path for such a small int;
// indices are small and non-negative.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// roleForSlot maps a held slot name to the Role it implies.
func roleForSlot(slotName string) Role {
	if slotName == LeaderSlotName {
		return Leader
	}
	return Tier1
}

// Prometheus metrics, registered at package init so they are always present
// even when the feature is disabled.
var (
	// gaugeRole is the acquirer's current role as a per-role gauge (exactly one
	// of the role label values is 1 at any time).
	gaugeRole = promutils.GetOrRegister(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_hierarchy_role",
		Help: "This Typha's hierarchical role: a per-role gauge, exactly one of " +
			"{leader,tier1,tier2} is 1 at any time.",
	}, []string{"role"}))

	// gaugeHeldSlot is an info-style gauge carrying the name of the slot (Lease)
	// this Typha currently holds (value always 1; the "none" label when it holds
	// nothing).  Doubles as the upstream-identity signal: a tier-1 holding
	// calico-typha-tier1-3 sources from the leader; a leader holds
	// calico-typha-leader; a tier-2 holds none and sources from the tier-1
	// Service.
	gaugeHeldSlot = promutils.GetOrRegister(prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "typha_hierarchy_held_slot",
		Help: "Info-style gauge carrying the name of the election slot (Lease) " +
			"this Typha holds (value always 1; slot=\"none\" when it holds nothing).",
	}, []string{"slot"}))
)

func setRoleGauge(r Role) {
	gaugeRole.WithLabelValues("leader").Set(b2f(r == Leader))
	gaugeRole.WithLabelValues("tier1").Set(b2f(r == Tier1))
	gaugeRole.WithLabelValues("tier2").Set(b2f(r == Tier2))
}

func setHeldSlotGauge(slot string) {
	gaugeHeldSlot.Reset()
	if slot == "" {
		slot = "none"
	}
	gaugeHeldSlot.WithLabelValues(slot).Set(1)
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Acquirer holds at most one slot and reports the implied Role.  Construct with
// New and run with Run.
type Acquirer struct {
	cfg        Config
	clientset  kubernetes.Interface
	newElector electorFactory

	// roles publishes Role transitions for the role manager to consume.  Same
	// drop-oldest-on-overflow semantics as leaderelection.Elector.roles.
	roles chan Role

	mu       sync.RWMutex
	heldSlot string // "" when we hold nothing
	role     Role

	// now is overridable in tests so lease-expiry checks are deterministic.
	now func() time.Time
}

// New constructs an Acquirer using real per-slot leaderelection.Electors.
func New(cs kubernetes.Interface, cfg Config) *Acquirer {
	cfg.applyDefaults()
	a := &Acquirer{
		cfg:       cfg,
		clientset: cs,
		roles:     make(chan Role, 16),
		role:      Tier2,
		now:       time.Now,
	}
	a.newElector = func(leaseName string) slotElector {
		return leaderelection.New(cs, leaderelection.Config{
			Enabled:        true,
			LeaseName:      leaseName,
			LeaseNamespace: cfg.LeaseNamespace,
			Identity:       cfg.Identity,
			LeaseDuration:  cfg.LeaseDuration,
			RenewDeadline:  cfg.RenewDeadline,
			RetryPeriod:    cfg.RetryPeriod,
		}, cfg.Identity, cfg.LeaseNamespace)
	}
	return a
}

// Roles returns the channel on which Role transitions are published.  Each send
// is edge-triggered: the consumer (role manager) converges to the latest value.
func (a *Acquirer) Roles() <-chan Role {
	return a.roles
}

// Role returns the role currently implied by the slot we hold (Tier2 if none).
func (a *Acquirer) Role() Role {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.role
}

// HeldSlot returns the name of the slot we currently hold and whether we hold
// one.  Used for metrics/diagnostics.
func (a *Acquirer) HeldSlot() (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.heldSlot, a.heldSlot != ""
}

// Run drives the acquirer until ctx is cancelled.  Call exactly once.
//
// The loop alternates between two phases:
//
//   - Watch phase (hold nothing): slowly list the leases; for each slot that
//     looks acquirable, start a campaign elector.  Stop as soon as we win one.
//   - Hold phase (hold a slot): keep only that slot's elector running.  Return
//     to the watch phase when we lose it.
func (a *Acquirer) Run(ctx context.Context) {
	log.WithFields(log.Fields{
		"identity":   a.cfg.Identity,
		"tier1Count": a.cfg.Tier1Count,
		"slots":      a.cfg.slotNames(),
	}).Info("Slot acquirer starting.")
	a.publish(Tier2)
	setRoleGauge(Tier2)
	setHeldSlotGauge("")

	for ctx.Err() == nil {
		a.watchAndCampaign(ctx)
	}
	log.Info("Slot acquirer stopping (context cancelled).")
}

// watchAndCampaign runs one full watch→campaign→hold→lose cycle.  It returns
// when we have lost the slot we held (so Run loops and starts watching again),
// or when the context is cancelled.
func (a *Acquirer) watchAndCampaign(ctx context.Context) {
	// Each campaign elector gets its OWN child context (cancelBySlot[slot]) so
	// that, the instant we win a slot, we can cancel every *other* campaign while
	// keeping the winner's elector running and renewing — no teardown/restart of
	// the winner, which would otherwise release-then-reacquire the lease and flap.
	cancelBySlot := map[string]context.CancelFunc{}
	roleEvents := make(chan slotRoleEvent, 64)
	var electorWG sync.WaitGroup

	// cancelAllExcept cancels every running campaign except keep (pass "" to
	// cancel all).  Used both on win (keep the winner) and on shutdown (keep
	// nothing).
	cancelAllExcept := func(keep string) {
		for slot, cancel := range cancelBySlot {
			if slot == keep {
				continue
			}
			cancel()
			delete(cancelBySlot, slot)
		}
	}
	defer func() {
		cancelAllExcept("")
		electorWG.Wait()
	}()

	startCampaign := func(slot string) {
		if _, ok := cancelBySlot[slot]; ok {
			return // Already campaigning for this slot.
		}
		slotCtx, cancel := context.WithCancel(ctx)
		cancelBySlot[slot] = cancel
		el := a.newElector(slot)
		electorWG.Add(1)
		go func() {
			defer electorWG.Done()
			el.Run(slotCtx)
		}()
		// Fan the elector's role channel into the merged channel, tagged with the
		// slot name, until this slot's context ends.
		electorWG.Add(1)
		go func() {
			defer electorWG.Done()
			for {
				select {
				case <-slotCtx.Done():
					return
				case r := <-el.Roles():
					select {
					case roleEvents <- slotRoleEvent{slot: slot, role: r}:
					case <-slotCtx.Done():
						return
					}
				}
			}
		}()
	}

	// Kick off an immediate scan so cold start doesn't wait WatchInterval.
	a.scanAndCampaign(ctx, startCampaign)

	ticker := time.NewTicker(a.cfg.WatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-scan: a slot may have freed up (holder died) since we last
			// looked.  Only starts NEW campaigns for newly-acquirable slots;
			// existing campaigns keep running.
			a.scanAndCampaign(ctx, startCampaign)
		case ev := <-roleEvents:
			if ev.role == leaderelection.Leader {
				// We won this slot.  Enter the hold phase: cancel every OTHER
				// campaign (this is the heart of "≤1 slot per candidate" — the
				// instant we win, we stop competing for anything else, releasing
				// any other slot we might have momentarily grabbed during the
				// dual-acquisition window).  Keep the winner's elector running.
				cancelAllExcept(ev.slot)
				a.holdSlot(ctx, ev.slot, roleEvents)
				return
			}
			// A campaign elector reported Follower (it never acquired, or it lost
			// a slot it briefly held before we noticed).  Cancel and forget it so
			// a later scan can restart it if the slot is still acquirable.
			if cancel, ok := cancelBySlot[ev.slot]; ok {
				cancel()
				delete(cancelBySlot, ev.slot)
			}
		}
	}
}

// holdSlot blocks while we hold slot, watching the (still-running) winning
// elector's role events on roleEvents.  It returns when that elector reports
// Follower (genuine loss of leadership) or the context is cancelled, after which
// watchAndCampaign's deferred cleanup tears the elector down and Run resumes the
// watch phase.
func (a *Acquirer) holdSlot(ctx context.Context, slot string, roleEvents <-chan slotRoleEvent) {
	role := roleForSlot(slot)
	log.WithFields(log.Fields{"slot": slot, "role": role}).Info("Won a slot; entering hold phase.")
	a.setHeld(slot, role)
	defer a.clearHeld()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-roleEvents:
			if ev.slot != slot {
				// Stray event from an other-slot campaign that hadn't fully torn
				// down yet; ignore (we already cancelled it).
				continue
			}
			if ev.role == leaderelection.Follower {
				log.WithField("slot", slot).Info("Lost held slot; demoting and resuming watch.")
				return
			}
			// Re-affirmation of Leader; nothing to do (still holding).
		}
	}
}

// scanAndCampaign lists the leases once and starts a campaign for every slot
// that currently looks acquirable (no holder or expired holder).  Slots that
// are already being campaigned for (tracked by startCampaign's idempotence) are
// not restarted.  This is the "lazy" gate: we only ever campaign for slots we
// have a realistic chance of winning, so full deployments generate no campaign
// traffic.
func (a *Acquirer) scanAndCampaign(ctx context.Context, startCampaign func(slot string)) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	leases, err := a.clientset.CoordinationV1().Leases(a.cfg.LeaseNamespace).List(
		listCtx, metav1.ListOptions{})
	if err != nil {
		// On a list error, fail toward making progress: campaign for every slot.
		// A transient API error must not wedge the deployment leaderless.  The
		// per-slot electors are themselves resilient and will sort out the single
		// holder; this only affects the (already rare) error path.
		log.WithError(err).Warn("Slot acquirer: failed to list leases; campaigning for all slots.")
		for _, slot := range a.cfg.slotNames() {
			startCampaign(slot)
		}
		return
	}

	bySlot := map[string]*coordinationv1.Lease{}
	for i := range leases.Items {
		l := &leases.Items[i]
		bySlot[l.Name] = l
	}

	for _, slot := range a.cfg.slotNames() {
		l := bySlot[slot]
		if a.slotAcquirable(l) {
			log.WithField("slot", slot).Debug("Slot looks acquirable; starting campaign.")
			startCampaign(slot)
		}
	}
}

// slotAcquirable reports whether the given lease (nil if it does not exist yet)
// looks like it can be acquired: it has no lease object, no holder, holds an
// empty holder identity, is held by us already, or the holder's lease has
// expired (renewTime + leaseDuration < now, with a small grace margin).
func (a *Acquirer) slotAcquirable(l *coordinationv1.Lease) bool {
	if l == nil {
		return true // No lease object yet — first acquirer creates it.
	}
	if l.Spec.HolderIdentity == nil || *l.Spec.HolderIdentity == "" {
		return true // Unheld.
	}
	if *l.Spec.HolderIdentity == a.cfg.Identity {
		return true // We already hold it (re-affirm).
	}
	// Held by someone else: acquirable only if the lease looks expired.
	if l.Spec.RenewTime == nil {
		return true // Malformed; treat as expired.
	}
	dur := a.cfg.LeaseDuration
	if l.Spec.LeaseDurationSeconds != nil {
		dur = time.Duration(*l.Spec.LeaseDurationSeconds) * time.Second
	}
	expiry := l.Spec.RenewTime.Time.Add(dur)
	return a.now().After(expiry)
}

// slotRoleEvent tags a role transition with the slot it came from so the watch
// loop can attribute wins/losses to the right slot.
type slotRoleEvent struct {
	slot string
	role leaderelection.Role
}

// setHeld records that we hold slot (with the given role) and publishes the role.
func (a *Acquirer) setHeld(slot string, role Role) {
	a.mu.Lock()
	a.heldSlot = slot
	a.role = role
	a.mu.Unlock()
	setRoleGauge(role)
	setHeldSlotGauge(slot)
	a.publish(role)
}

// clearHeld records that we hold nothing and publishes Tier2.
func (a *Acquirer) clearHeld() {
	a.mu.Lock()
	a.heldSlot = ""
	a.role = Tier2
	a.mu.Unlock()
	setRoleGauge(Tier2)
	setHeldSlotGauge("")
	a.publish(Tier2)
}

// publish sends a role on the roles channel, dropping the oldest pending value
// if the consumer is slow (mirrors leaderelection.Elector.publish).
func (a *Acquirer) publish(r Role) {
	select {
	case a.roles <- r:
	default:
		select {
		case <-a.roles:
		default:
		}
		a.roles <- r
	}
}
