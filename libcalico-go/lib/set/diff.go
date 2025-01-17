// Copyright (c) 2019 Tigera, Inc. All rights reserved.
package set

// IterDifferences iterates through the set of items that are in A but not in B, and the set that are in B but not in A.
func IterDifferences[T comparable](a, b Set[T], aNotB, bNotA func(item T) error) {
	a.Iter(func(item T) error {
		if !b.Contains(item) {
			return aNotB(item)
		}
		return nil
	})
	b.Iter(func(item T) error {
		if !a.Contains(item) {
			return bNotA(item)
		}
		return nil
	})
}
