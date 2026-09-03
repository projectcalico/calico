// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Tests below must NOT be parallel since they mutate package-level vars.

func TestRunBuildCleanup(t *testing.T) {
	t.Run("LIFO order and error collection", func(t *testing.T) {
		buildCleanupFns = nil
		defer func() { buildCleanupFns = nil }()

		var order []int
		buildCleanupFns = append(buildCleanupFns, func(ctx context.Context) error {
			order = append(order, 1)
			return errors.New("cleanup-1 failed")
		})
		buildCleanupFns = append(buildCleanupFns, func(ctx context.Context) error {
			order = append(order, 2)
			return nil
		})
		buildCleanupFns = append(buildCleanupFns, func(ctx context.Context) error {
			order = append(order, 3)
			return errors.New("cleanup-3 failed")
		})

		err := runBuildCleanup(context.Background())
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "cleanup-1 failed") {
			t.Fatalf("missing cleanup-1 error: %v", err)
		}
		if !strings.Contains(err.Error(), "cleanup-3 failed") {
			t.Fatalf("missing cleanup-3 error: %v", err)
		}
		if !slices.Equal(order, []int{3, 2, 1}) {
			t.Fatalf("expected LIFO order [3, 2, 1], got %v", order)
		}
		if buildCleanupFns != nil {
			t.Fatal("expected buildCleanupFns to be nil after cleanup")
		}
	})

	t.Run("empty slice is no-op", func(t *testing.T) {
		buildCleanupFns = nil
		if err := runBuildCleanup(context.Background()); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("propagates context cancellation", func(t *testing.T) {
		buildCleanupFns = nil
		defer func() { buildCleanupFns = nil }()

		buildCleanupFns = append(buildCleanupFns, func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return nil
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := runBuildCleanup(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	})
}
