// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package v3

import (
	"runtime"
	"sync"
	"testing"
)

// TestCRDValidatorsMemory verifies that compiling all CRD validators stays
// within a reasonable memory budget. CEL compilation cost scales with
// maxItems/maxLength annotations on CRD schemas — if those bounds grow
// too large the compilation can consume hundreds of megabytes.
func TestCRDValidatorsMemory(t *testing.T) {
	resetCRDValidationState()
	SetCRDValidationEnabled(true)

	// Load schemas so we can iterate all Kinds.
	schemasOnce.Do(loadSchemas)
	if schemasErr != nil {
		t.Fatalf("failed to load schemas: %v", schemasErr)
	}

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	// Force every Kind to compile.
	for kind, entry := range kindEntries {
		entry.once.Do(func() { entry.compile(kind) })
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	allocMB := float64(after.TotalAlloc-before.TotalAlloc) / (1024 * 1024)
	t.Logf("CRD validator compilation allocated %.1f MB (%d Kinds)", allocMB, len(kindEntries))

	const budgetMB = 100.0
	if allocMB > budgetMB {
		t.Errorf("CRD validator compilation allocated %.1f MB, exceeding %.0f MB budget; CEL compilation is too expensive", allocMB, budgetMB)
	}
}

// resetCRDValidationState resets all CRD validation state so tests can
// measure fresh initialization.
func resetCRDValidationState() {
	crdValidationEnabled.Store(false)
	kindEntries = nil
	schemasOnce = sync.Once{}
	schemasErr = nil
}
