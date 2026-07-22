// Copyright (c) 2024-2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables_test

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"

	"github.com/projectcalico/calico/felix/ip"
)

func ptr[A any](v A) *A { return &v }

func NewFake(fam knftables.Family, name string) *fakeNFT {
	return &fakeNFT{
		family:          fam,
		name:            name,
		fake:            knftables.NewFake(fam, name),
		transactions:    make([]knftables.Transaction, 0),
		Time:            time.Unix(0, 0),
		CumulativeSleep: 0,
	}
}

type fakeNFT struct {
	lock sync.Mutex

	// Wrap a knftables fake instance.
	fake   *knftables.Fake
	family knftables.Family
	name   string

	// Also track other information.
	transactions []knftables.Transaction

	// Track the current time.
	Time            time.Time
	CumulativeSleep time.Duration

	// Allow execution of code in the path of various nftables methods.
	PreWrite func()
	PreList  func()

	// Allow overriding the next ListElements response for one or more sets to be an error.
	ListElementsErrors map[string]error

	// Allow overriding the next ListAll response to be an error.
	ListAllError error

	// Track the number of List calls (simulates nft process spawns).
	ListCallCount int
}

func (f *fakeNFT) Reset() {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.transactions = make([]knftables.Transaction, 0)
}

func (f *fakeNFT) Sleep(duration time.Duration) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.CumulativeSleep += duration
	f.Time = f.Time.Add(duration)
	logrus.WithField("time", f.Time).Info("Updated current time after sleep")
}

func (f *fakeNFT) Now() time.Time {
	f.lock.Lock()
	defer f.lock.Unlock()

	return f.Time
}

func (f *fakeNFT) AdvanceTimeBy(amount time.Duration) {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.Time = f.Time.Add(amount)
	logrus.WithField("time", f.Time).Info("Updated current time")
}

func (f *fakeNFT) Fake() *knftables.Fake {
	return f.fake
}

func (f *fakeNFT) NewTransaction() *knftables.Transaction {
	return f.fake.NewTransaction()
}

// Run runs a Transaction and returns the result. The IsNotFound and
// IsAlreadyExists methods can be used to test the result.
func (f *fakeNFT) Run(ctx context.Context, tx *knftables.Transaction) error {
	f.preRun(tx)

	// Real nftables interval sets (those created with knftables.IntervalFlag) reject
	// overlapping or nested elements with EEXIST, but the upstream knftables fake does
	// not model this. Replay the transaction against a throwaway copy of the current
	// state and fail here if it would leave any interval set holding overlapping members,
	// so tests observe the same failure production hits against real nftables.
	if err := f.checkIntervalOverlaps(ctx, tx); err != nil {
		return err
	}

	return f.fake.Run(ctx, tx)
}

// checkIntervalOverlaps replays tx against a copy of the current dataplane state and
// returns an nftables-style "File exists" error if any interval set would end up holding
// overlapping members. It returns nil when tx would fail upstream validation anyway (the
// real Run then surfaces that error) or when no interval set is affected.
func (f *fakeNFT) checkIntervalOverlaps(ctx context.Context, tx *knftables.Transaction) error {
	shadow := knftables.NewFake(f.family, f.name)
	if dump := f.fake.Dump(); dump != "" {
		if err := shadow.ParseDump(dump); err != nil {
			return fmt.Errorf("nftables fake: snapshotting state for interval-set check: %w", err)
		}
	}

	if err := shadow.Run(ctx, tx); err != nil {
		// Not an interval-overlap problem; let the real Run reproduce this error.
		return nil
	}
	if shadow.Table == nil {
		return nil
	}

	for name, s := range shadow.Table.Sets {
		if !isIntervalSet(s) {
			continue
		}
		if err := checkIntervalSetOverlap(name, s.Elements); err != nil {
			return err
		}
	}
	return nil
}

func isIntervalSet(s *knftables.FakeSet) bool {
	for _, flag := range s.Flags {
		if flag == knftables.IntervalFlag {
			return true
		}
	}
	return false
}

// checkIntervalSetOverlap returns an nft-like EEXIST error if any two elements of an
// interval set overlap or nest. Elements whose keys aren't plain CIDRs are ignored: Felix
// only ever puts single CIDRs (hash:net members) in interval sets.
func checkIntervalSetOverlap(setName string, elements []*knftables.Element) error {
	cidrs := make([]ip.CIDR, 0, len(elements))
	for _, element := range elements {
		if len(element.Key) != 1 {
			continue
		}
		cidr, err := ip.ParseCIDROrIP(element.Key[0])
		if err != nil {
			continue
		}
		cidrs = append(cidrs, cidr)
	}

	for i := range cidrs {
		for j := i + 1; j < len(cidrs); j++ {
			if cidrsOverlap(cidrs[i], cidrs[j]) {
				return fmt.Errorf("add element to set %q: %s overlaps %s: File exists", setName, cidrs[i], cidrs[j])
			}
		}
	}
	return nil
}

// cidrsOverlap reports whether a and b overlap: the one with the shorter prefix contains
// the other's network address (nesting in either direction, or an exact match). CIDRs of
// different families never overlap.
func cidrsOverlap(a, b ip.CIDR) bool {
	if a.Prefix() <= b.Prefix() {
		return a.Contains(b.Addr())
	}
	return b.Contains(a.Addr())
}

func (f *fakeNFT) preRun(tx *knftables.Transaction) {
	f.lock.Lock()
	defer f.lock.Unlock()

	if f.PreWrite != nil {
		logrus.Info("Calling PreWrite")
		f.PreWrite()
		f.PreWrite = nil
	}
	f.transactions = append(f.transactions, *tx)
}

// Check does a dry-run of a Transaction (as with `nft --check`) and returns the
// result. The IsNotFound and IsAlreadyExists methods can be used to test the
// result.
func (f *fakeNFT) Check(ctx context.Context, tx *knftables.Transaction) error {
	return f.fake.Check(ctx, tx)
}

// ListAll returns a map containing the names of all objects in the table,
// grouped by object type.
func (f *fakeNFT) ListAll(ctx context.Context) (map[string][]string, error) {
	f.preList()
	if err := f.takeListAllError(); err != nil {
		logrus.WithError(err).Info("Returning test error from ListAll")
		return nil, err
	}
	return f.fake.ListAll(ctx)
}

func (f *fakeNFT) takeListAllError() error {
	f.lock.Lock()
	defer f.lock.Unlock()

	err := f.ListAllError
	f.ListAllError = nil
	return err
}

// List returns a list of the names of the objects of objectType ("chain", "set",
// or "map") in the table. If there are no such objects, this will return an empty
// list and no error.
func (f *fakeNFT) List(ctx context.Context, objectType string) ([]string, error) {
	f.preList()
	return f.fake.List(ctx, objectType)
}

func (f *fakeNFT) preList() {
	f.lock.Lock()
	defer f.lock.Unlock()

	f.ListCallCount++

	if f.PreList != nil {
		logrus.Info("Calling PreList")
		f.PreList()
		f.PreList = nil
	}
}

// ListRules returns a list of the rules in a chain, in order. If no chain name is
// specified, then all rules within the table will be returned. Note that at the
// present time, the Rule objects will have their `Comment` and `Handle` fields
// filled in, but *not* the actual `Rule` field. So this can only be used to find
// the handles of rules if they have unique comments to recognize them by, or if
// you know the order of the rules within the chain. If the chain exists but
// contains no rules, this will return an empty list and no error.
func (f *fakeNFT) ListRules(ctx context.Context, chain string) ([]*knftables.Rule, error) {
	return f.fake.ListRules(ctx, chain)
}

// ListElements returns a list of the elements in a set or map. (objectType should
// be "set" or "map".) If the set/map exists but contains no elements, this will
// return an empty list and no error.
func (f *fakeNFT) ListElements(ctx context.Context, objectType string, name string) ([]*knftables.Element, error) {
	if err := f.maybeFailListElements(name); err != nil {
		return nil, err
	}
	return f.fake.ListElements(ctx, objectType, name)
}

func (f *fakeNFT) maybeFailListElements(name string) error {
	f.lock.Lock()
	defer f.lock.Unlock()

	if err := f.ListElementsErrors[name]; err != nil {
		logrus.WithError(err).WithField("name", name).Info("Returning test error from ListElements")
		delete(f.ListElementsErrors, name)
		return err
	}
	return nil
}

func (f *fakeNFT) ListCounters(ctx context.Context) ([]*knftables.Counter, error) {
	return f.fake.ListCounters(ctx)
}
