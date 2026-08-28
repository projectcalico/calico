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

func TestExtractGitHashFromVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		version string
		want    string
		wantErr bool
	}{
		{
			version: "v3.22.1",
			wantErr: true,
		},
		{
			version: "v3.22.0-1.0",
			wantErr: true,
		},
		{
			version: "v3.22.0-gshorthash",
			wantErr: true,
		},
		{
			version: "v3.22.0-glonghashthatisnotvalid",
			wantErr: true,
		},
		{
			version: "v3.22.1-25-g997f6be93484-extra",
			wantErr: true,
		},
		{
			version: "v3.22.1-25-g997f6be93484-dirty",
			wantErr: true,
		},
		{
			version: "v3.22.1-948-g997f6be93484",
			want:    "997f6be93484",
		},
		{
			version: "v3.22.1-calient-0.dev-948-g1234567890ab",
			want:    "1234567890ab",
		},
		{
			version: "v3.23.0-2.0-calient-0.dev-948-gabcdef123456",
			want:    "abcdef123456",
		},
	}

	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			got, err := extractGitHashFromVersion(tc.version)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("extractGitHashFromVersion(%q) = %q, want %q", tc.version, got, tc.want)
			}
		})
	}
}

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
