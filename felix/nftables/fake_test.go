// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/knftables"
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
}

func (f *fakeNFT) Reset() {
	f.transactions = make([]knftables.Transaction, 0)
}

func (f *fakeNFT) Sleep(duration time.Duration) {
	f.CumulativeSleep += duration
	f.Time = f.Time.Add(duration)
	logrus.WithField("time", f.Time).Info("Updated current time after sleep")
}

func (f *fakeNFT) Now() time.Time {
	return f.Time
}

func (f *fakeNFT) AdvanceTimeBy(amount time.Duration) {
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
	if f.PreWrite != nil {
		logrus.Info("Calling PreWrite")
		f.PreWrite()
		f.PreWrite = nil
	}
	f.transactions = append(f.transactions, *tx)
	return f.fake.Run(ctx, tx)
}

// Check does a dry-run of a Transaction (as with `nft --check`) and returns the
// result. The IsNotFound and IsAlreadyExists methods can be used to test the
// result.
func (f *fakeNFT) Check(ctx context.Context, tx *knftables.Transaction) error {
	return f.fake.Check(ctx, tx)
}

// List returns a list of the names of the objects of objectType ("chain", "set",
// or "map") in the table. If there are no such objects, this will return an empty
// list and no error.
func (f *fakeNFT) List(ctx context.Context, objectType string) ([]string, error) {
	if f.PreList != nil {
		logrus.Info("Calling PreList")
		f.PreList()
		f.PreList = nil
	}
	return f.fake.List(ctx, objectType)
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
	return f.fake.ListElements(ctx, objectType, name)
}
