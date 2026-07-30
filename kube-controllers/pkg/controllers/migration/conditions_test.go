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

package migration

import (
	"fmt"
	"testing"
)

func conflictInfos(n int) []ConflictInfo {
	infos := make([]ConflictInfo, 0, n)
	for i := 0; i < n; i++ {
		infos = append(infos, ConflictInfo{Kind: "Tier", Name: fmt.Sprintf("tier-%d", i)})
	}
	return infos
}

func TestConflictConditions_Empty(t *testing.T) {
	conditions := conflictConditions(nil)
	if conditions != nil {
		t.Fatalf("expected nil conditions for no conflicts, got %+v", conditions)
	}
}

func TestConflictConditions_One(t *testing.T) {
	conditions := conflictConditions(conflictInfos(1))
	if len(conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(conditions))
	}
	if conditions[0].Reason != conditionReasonResourceMismatch {
		t.Errorf("expected reason %s, got %s", conditionReasonResourceMismatch, conditions[0].Reason)
	}
}

// TestConflictConditions_ExactlyAtCap and TestConflictConditions_OverCap use
// the literal 32 (not the maxConflictConditions constant) so that a change to
// the cap itself is caught here, not just carried through.
func TestConflictConditions_ExactlyAtCap(t *testing.T) {
	conditions := conflictConditions(conflictInfos(32))
	if len(conditions) != 32 {
		t.Fatalf("expected 32 conditions, got %d", len(conditions))
	}
	for _, c := range conditions {
		if c.Reason != conditionReasonResourceMismatch {
			t.Errorf("expected reason %s at cap, got %s", conditionReasonResourceMismatch, c.Reason)
		}
	}
}

func TestConflictConditions_OverCap(t *testing.T) {
	conditions := conflictConditions(conflictInfos(33))

	// 32 per-resource conditions plus one truncation summary, not 33
	// per-resource conditions: the count actually emitted must stay at 33.
	if len(conditions) != 33 {
		t.Fatalf("expected 33 conditions (32 + summary), got %d", len(conditions))
	}

	for _, c := range conditions[:32] {
		if c.Reason != conditionReasonResourceMismatch {
			t.Errorf("expected reason %s for per-resource conditions, got %s", conditionReasonResourceMismatch, c.Reason)
		}
	}

	summary := conditions[32]
	if summary.Reason != conditionReasonConflictsOmitted {
		t.Errorf("expected summary reason %s, got %s", conditionReasonConflictsOmitted, summary.Reason)
	}
	if summary.Type != conditionTypeConflict {
		t.Errorf("expected summary type %s, got %s", conditionTypeConflict, summary.Type)
	}
	wantMessage := "1 more conflicts not shown"
	if summary.Message != wantMessage {
		t.Errorf("expected summary message %q, got %q", wantMessage, summary.Message)
	}
}
