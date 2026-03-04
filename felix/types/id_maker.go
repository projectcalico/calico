// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package types

// IDMaker is a simple interface for types that can provide an ID string. Used for functions that accept either a
// PolicyID or ProfileID.
type IDMaker interface {
	ID() string
}
