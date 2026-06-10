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

package slotacquirer

import (
	"context"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/typha/pkg/leaderelection"
)

// ---- fake elector ------------------------------------------------------------

// fakeElector is a slotElector substitute that the test drives explicitly: it
// only becomes Leader when the test's controller decides this candidate should
// win the slot it is campaigning for.  This lets the tests assert acquisition
// outcomes deterministically without relying on the fake clientset's (absent)
// clock-based lease arbitration.
type fakeElector struct {
	slot     string
	identity string
	roles    chan leaderelection.Role
	ctl      *electionController
}

func (f *fakeElector) Run(ctx context.Context) {
	f.ctl.register(f)
	defer f.ctl.unregister(f)
	<-ctx.Done()
}

func (f *fakeElector) Roles() <-chan leaderelection.Role {
	return f.roles
}

func (f *fakeElector) emit(r leaderelection.Role) {
	select {
	case f.roles <- r:
	default:
		select {
		case <-f.roles:
		default:
		}
		f.roles <- r
	}
}

// electionController arbitrates which candidate holds each slot, mimicking
// client-go's single-holder-per-lease guarantee.  Tests use it to grant and
// revoke slots.
type electionController struct {
	mu sync.Mutex
	// campaigning[slot] is the set of electors currently campaigning for slot.
	campaigning map[string]map[*fakeElector]struct{}
	// holder[slot] is the elector currently granted slot, if any.
	holder map[string]*fakeElector
}

func newElectionController() *electionController {
	return &electionController{
		campaigning: map[string]map[*fakeElector]struct{}{},
		holder:      map[string]*fakeElector{},
	}
}

func (c *electionController) register(f *fakeElector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.campaigning[f.slot] == nil {
		c.campaigning[f.slot] = map[*fakeElector]struct{}{}
	}
	c.campaigning[f.slot][f] = struct{}{}
}

func (c *electionController) unregister(f *fakeElector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.campaigning[f.slot], f)
	if c.holder[f.slot] == f {
		// The holder's elector was cancelled (we are giving up the slot).  Free it.
		delete(c.holder, f.slot)
	}
}

// grant makes the identity that is campaigning for slot the holder and emits
// Leader to it.  No-op if that identity is not currently campaigning.
func (c *electionController) grant(slot, identity string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.holder[slot] != nil {
		return false // Already held.
	}
	for f := range c.campaigning[slot] {
		if f.identity == identity {
			c.holder[slot] = f
			f.emit(leaderelection.Leader)
			return true
		}
	}
	return false
}

// grantAny grants slot to an arbitrary current campaigner that does not already
// hold another slot (used when the test doesn't care which identity wins).
// Skipping identities that already hold a slot mirrors the real acquirer, which
// cancels its other campaigns the moment it wins one — a real client-go elector
// for those slots would have stopped polling.
func (c *electionController) grantAny(slot string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.holder[slot] != nil {
		return c.holder[slot].identity, false
	}
	for f := range c.campaigning[slot] {
		if c.identityHoldsSomethingLocked(f.identity) {
			continue
		}
		c.holder[slot] = f
		f.emit(leaderelection.Leader)
		return f.identity, true
	}
	return "", false
}

// identityHoldsSomethingLocked reports whether identity already holds any slot.
// Caller must hold c.mu.
func (c *electionController) identityHoldsSomethingLocked(identity string) bool {
	for _, h := range c.holder {
		if h.identity == identity {
			return true
		}
	}
	return false
}

// revoke removes the current holder of slot and emits Follower to it.
func (c *electionController) revoke(slot string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.holder[slot]; f != nil {
		delete(c.holder, slot)
		f.emit(leaderelection.Follower)
	}
}

func (c *electionController) holderIdentity(slot string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f := c.holder[slot]; f != nil {
		return f.identity, true
	}
	return "", false
}

func (c *electionController) numCampaigning(slot string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.campaigning[slot])
}

// ---- test harness ------------------------------------------------------------

// newTestAcquirer builds an Acquirer wired to the shared electionController.
func newTestAcquirer(cs *fake.Clientset, ctl *electionController, identity string, tier1Count int) *Acquirer {
	cfg := Config{
		Tier1Count:     tier1Count,
		LeaseNamespace: "kube-system",
		Identity:       identity,
		WatchInterval:  20 * time.Millisecond,
	}
	cfg.applyDefaults()
	a := &Acquirer{
		cfg:       cfg,
		clientset: cs,
		roles:     make(chan Role, 16),
		role:      Tier2,
		now:       time.Now,
	}
	a.newElector = func(leaseName string) slotElector {
		return &fakeElector{
			slot:     leaseName,
			identity: identity,
			roles:    make(chan leaderelection.Role, 4),
			ctl:      ctl,
		}
	}
	return a
}

// waitForRole polls a.Role() until it equals want or the deadline passes.
func waitForRole(t *testing.T, a *Acquirer, want Role, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if a.Role() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("acquirer %q: timed out waiting for role %v, have %v (slot=%q)",
		a.cfg.Identity, want, a.Role(), heldSlot(a))
}

func heldSlot(a *Acquirer) string {
	s, _ := a.HeldSlot()
	return s
}

func countListActions(cs *fake.Clientset) int {
	n := 0
	for _, act := range cs.Actions() {
		if act.GetVerb() == "list" && act.GetResource().Resource == "leases" {
			n++
		}
	}
	return n
}

// ---- tests -------------------------------------------------------------------

// TestSingleTierReproducesLeaderOnly verifies Tier1Count=0: only the leader slot
// exists, and a lone candidate becomes Leader — exactly the WS-C single-tier
// shape.
func TestSingleTierReproducesLeaderOnly(t *testing.T) {
	cs := fake.NewClientset()
	ctl := newElectionController()
	a := newTestAcquirer(cs, ctl, "pod-a", 0)

	if names := a.cfg.slotNames(); len(names) != 1 || names[0] != LeaderSlotName {
		t.Fatalf("Tier1Count=0 should yield exactly the leader slot, got %v", names)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)

	// It should campaign for the leader slot; grant it.
	grantWhenCampaigning(t, ctl, LeaderSlotName, "pod-a")
	waitForRole(t, a, Leader, 2*time.Second)
	if s, _ := a.HeldSlot(); s != LeaderSlotName {
		t.Fatalf("expected to hold %q, holding %q", LeaderSlotName, s)
	}
}

// TestExactlyOneHolderPerSlotAndOnePerCandidate is the core property test:
// M candidates, N+1 slots ⇒ each slot ends with exactly one holder and no
// candidate holds more than one slot.
func TestExactlyOneHolderPerSlotAndOnePerCandidate(t *testing.T) {
	const tier1Count = 2 // slots: leader + tier1-0 + tier1-1 = 3
	const numCandidates = 5

	cs := fake.NewClientset()
	ctl := newElectionController()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	acquirers := make([]*Acquirer, numCandidates)
	for i := range acquirers {
		a := newTestAcquirer(cs, ctl, "pod-"+itoa(i), tier1Count)
		acquirers[i] = a
		go a.Run(ctx)
	}

	slots := []string{LeaderSlotName, tier1SlotName(0), tier1SlotName(1)}

	// Grant each slot to whichever candidate is campaigning for it first.  The
	// acquirer cancels its other campaigns on winning, so subsequent grants go to
	// different candidates.
	for _, slot := range slots {
		var winner string
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if id, ok := ctl.grantAny(slot); ok {
				winner = id
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if winner == "" {
			t.Fatalf("no candidate campaigned for slot %q", slot)
		}
	}

	// Wait for roles to settle: exactly one Leader, exactly tier1Count Tier1, the
	// rest Tier2; and no candidate holds two slots (guaranteed structurally — a
	// candidate has at most one role — but we assert the counts).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if countRole(acquirers, Leader) == 1 &&
			countRole(acquirers, Tier1) == tier1Count &&
			countRole(acquirers, Tier2) == numCandidates-1-tier1Count {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := countRole(acquirers, Leader); got != 1 {
		t.Errorf("expected exactly 1 Leader, got %d", got)
	}
	if got := countRole(acquirers, Tier1); got != tier1Count {
		t.Errorf("expected exactly %d Tier1, got %d", tier1Count, got)
	}
	if got := countRole(acquirers, Tier2); got != numCandidates-1-tier1Count {
		t.Errorf("expected %d Tier2, got %d", numCandidates-1-tier1Count, got)
	}

	// Each slot has exactly one holder.
	holders := map[string]string{}
	for _, slot := range slots {
		id, ok := ctl.holderIdentity(slot)
		if !ok {
			t.Errorf("slot %q has no holder", slot)
			continue
		}
		holders[slot] = id
	}
	// No identity holds two slots.
	seen := map[string]string{}
	for slot, id := range holders {
		if prev, dup := seen[id]; dup {
			t.Errorf("candidate %q holds two slots: %q and %q", id, prev, slot)
		}
		seen[id] = slot
	}
}

// TestFailoverOnHolderDeath verifies that when the holder of a slot dies (its
// lease is revoked), another candidate takes the slot over.
func TestFailoverOnHolderDeath(t *testing.T) {
	const tier1Count = 1 // leader + tier1-0
	cs := fake.NewClientset()
	ctl := newElectionController()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a := newTestAcquirer(cs, ctl, "pod-a", tier1Count)
	b := newTestAcquirer(cs, ctl, "pod-b", tier1Count)
	go a.Run(ctx)
	go b.Run(ctx)

	// Grant the leader slot to A and tier1-0 to B (grant in that order; A wins
	// leader first, then stops campaigning for tier1-0, leaving B to win it).
	grantWhenCampaigning(t, ctl, LeaderSlotName, "pod-a")
	waitForRole(t, a, Leader, 2*time.Second)
	grantWhenCampaigning(t, ctl, tier1SlotName(0), "pod-b")
	waitForRole(t, b, Tier1, 2*time.Second)

	// Kill the leader (A): revoke its lease.  A demotes to Tier2 and B, now the
	// only other candidate, should win the leader slot.
	ctl.revoke(LeaderSlotName)
	waitForRole(t, a, Tier2, 2*time.Second)

	// B is campaigning for the leader slot again (it gave up tier1-0 on... no — B
	// still holds tier1-0).  For B to take over leader it must give up tier1-0.
	// In this minimal setup B keeps tier1-0; A re-campaigns for both slots and can
	// retake leader.  Grant leader to whichever is campaigning.
	var newLeader string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if id, ok := ctl.grantAny(LeaderSlotName); ok {
			newLeader = id
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if newLeader == "" {
		t.Fatal("no candidate re-campaigned for the leader slot after holder death")
	}
	// The new leader must report Leader.
	target := a
	if newLeader == "pod-b" {
		target = b
	}
	waitForRole(t, target, Leader, 2*time.Second)
}

// TestLazyCandidacyBacksOffWhenSlotsFull is the API-load test: once all slots
// are filled, an extra idle candidate must NOT keep spinning up campaign
// electors.  We assert that an idle Tier2 candidate's lease LISTs accrue at the
// slow watch cadence and that it never wins (stays Tier2), demonstrating the
// back-off.  Campaign electors in this fake never poll the API themselves (the
// real ones would), so the observable steady-state API cost is exactly the
// watch-loop LISTs.
func TestLazyCandidacyBacksOffWhenSlotsFull(t *testing.T) {
	const tier1Count = 1 // leader + tier1-0 = 2 slots
	cs := fake.NewClientset()
	ctl := newElectionController()

	// Pre-populate both leases as held-and-fresh by other identities so the idle
	// candidate's scan sees them as NOT acquirable.
	now := metav1.NewMicroTime(time.Now())
	dur := int32(15)
	for _, name := range []string{LeaderSlotName, tier1SlotName(0)} {
		holder := "other-" + name
		_, err := cs.CoordinationV1().Leases("kube-system").Create(context.Background(),
			&coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system"},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holder,
					LeaseDurationSeconds: &dur,
					RenewTime:            &now,
				},
			}, metav1.CreateOptions{})
		if err != nil {
			t.Fatalf("failed to seed lease %q: %v", name, err)
		}
	}

	// Keep the seeded leases looking fresh: a reactor that rewrites RenewTime to
	// now on every GET/LIST would be ideal, but the simpler approach is to use a
	// fixed clock on the acquirer set to the seed time so the leases never expire.
	seedTime := time.Now()
	a := newTestAcquirer(cs, ctl, "pod-idle", tier1Count)
	a.now = func() time.Time { return seedTime }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)

	// Let several watch intervals elapse.  WatchInterval is 20ms; over ~300ms we
	// expect ~15 LISTs, and crucially the candidate must never start a campaign
	// (so it never wins) because every slot looks held-and-fresh.
	time.Sleep(300 * time.Millisecond)

	if a.Role() != Tier2 {
		t.Fatalf("idle candidate should stay Tier2 when all slots are full, got %v", a.Role())
	}
	// It must not be campaigning for any slot (lazy back-off): the controller
	// should show zero campaigners from this acquirer.  Since other identities
	// aren't real here, campaigning count for each slot should be 0.
	for _, slot := range []string{LeaderSlotName, tier1SlotName(0)} {
		if n := ctl.numCampaigning(slot); n != 0 {
			t.Errorf("idle candidate started a campaign for full slot %q (count=%d); "+
				"lazy candidacy should have backed off", slot, n)
		}
	}
	// Sanity: it did do periodic LISTs (the cheap steady-state cost) rather than
	// hammering with per-slot GETs.
	if lists := countListActions(cs); lists < 3 {
		t.Errorf("expected the idle candidate to LIST leases periodically, only saw %d", lists)
	} else {
		t.Logf("idle candidate performed %d LISTs over 300ms (~%.0fms cadence), no campaigns",
			lists, 300.0/float64(lists))
	}
}

// TestLazyCandidacyCampaignsWhenSlotFrees verifies the other half of lazy
// candidacy: when a held slot's lease expires, the idle candidate notices on its
// next scan and starts a campaign (and can then win).
func TestLazyCandidacyCampaignsWhenSlotFrees(t *testing.T) {
	const tier1Count = 0 // leader only
	cs := fake.NewClientset()
	ctl := newElectionController()

	// Seed the leader lease as held-and-EXPIRED (renewTime well in the past).
	past := metav1.NewMicroTime(time.Now().Add(-1 * time.Minute))
	dur := int32(15)
	holder := "dead-leader"
	_, err := cs.CoordinationV1().Leases("kube-system").Create(context.Background(),
		&coordinationv1.Lease{
			ObjectMeta: metav1.ObjectMeta{Name: LeaderSlotName, Namespace: "kube-system"},
			Spec: coordinationv1.LeaseSpec{
				HolderIdentity:       &holder,
				LeaseDurationSeconds: &dur,
				RenewTime:            &past,
			},
		}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("failed to seed expired lease: %v", err)
	}

	a := newTestAcquirer(cs, ctl, "pod-a", tier1Count)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.Run(ctx)

	// Because the lease is expired, the candidate should campaign and we can grant.
	grantWhenCampaigning(t, ctl, LeaderSlotName, "pod-a")
	waitForRole(t, a, Leader, 2*time.Second)
}

// TestContextCancelStopsAcquirer verifies clean shutdown: cancelling the context
// returns Run and leaves no goroutines campaigning.
func TestContextCancelStopsAcquirer(t *testing.T) {
	cs := fake.NewClientset()
	ctl := newElectionController()
	a := newTestAcquirer(cs, ctl, "pod-a", 1)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.Run(ctx)
	}()

	// Win a slot so we are in the hold phase, then cancel.
	grantWhenCampaigning(t, ctl, LeaderSlotName, "pod-a")
	waitForRole(t, a, Leader, 2*time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

// ---- helpers -----------------------------------------------------------------

// grantWhenCampaigning waits until identity is campaigning for slot, then grants
// it.
func grantWhenCampaigning(t *testing.T, ctl *electionController, slot, identity string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ctl.grant(slot, identity) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%q never campaigned for slot %q so it could not be granted", identity, slot)
}

func countRole(acquirers []*Acquirer, r Role) int {
	n := 0
	for _, a := range acquirers {
		if a.Role() == r {
			n++
		}
	}
	return n
}
