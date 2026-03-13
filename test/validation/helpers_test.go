// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package validation_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

var nameCounter atomic.Int64

// uniqueName returns a unique name for a test object to avoid collisions between subtests.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, nameCounter.Add(1))
}

// mustCreate creates an object and registers cleanup to delete it.
func mustCreate(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	if err := testClient.Create(ctx, obj); err != nil {
		t.Fatalf("expected creation to succeed but got: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup; the object may already be gone.
		_ = testClient.Delete(context.Background(), obj)
	})
}

// expectCreateFails asserts that creating the object fails and the error contains msgSubstring.
func expectCreateFails(t *testing.T, obj client.Object, msgSubstring string) {
	t.Helper()
	ctx := context.Background()
	err := testClient.Create(ctx, obj)
	if err == nil {
		_ = testClient.Delete(ctx, obj) // clean up the unexpectedly-created object
		t.Fatalf("expected creation to fail with %q, but it succeeded", msgSubstring)
	}
	if !strings.Contains(err.Error(), msgSubstring) {
		t.Fatalf("expected error containing %q, got: %v", msgSubstring, err)
	}
}

// expectCreateSucceeds asserts that creating the object succeeds, then deletes it.
func expectCreateSucceeds(t *testing.T, obj client.Object) {
	t.Helper()
	ctx := context.Background()
	if err := testClient.Create(ctx, obj); err != nil {
		t.Fatalf("expected creation to succeed but got: %v", err)
	}
	// Clean up immediately; we only needed to verify the create succeeded.
	_ = testClient.Delete(ctx, obj)
}
