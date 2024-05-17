package nftables_test

import (
	"context"

	"sigs.k8s.io/knftables"
)

func ptr[A any](v A) *A { return &v }

func NewFake(fam knftables.Family, name string) *fakeNFT {
	return &fakeNFT{
		fake:         knftables.NewFake(fam, name),
		transactions: make([]knftables.Transaction, 0),
	}
}

type fakeNFT struct {
	// Wrap a knftables fake instance.
	fake *knftables.Fake

	// Also track other information.
	transactions []knftables.Transaction
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
	return f.ListElements(ctx, objectType, name)
}
