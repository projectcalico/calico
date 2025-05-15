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

package testutil

import (
	"encoding/json"
	"testing"
)

func MustMarshal(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Failed to marshal %#v: %v", v, err)
	}

	return string(b)
}

func MustUnmarshal[E any](t *testing.T, byts []byte) *E {
	e := new(E)
	if err := json.Unmarshal(byts, e); err != nil {
		t.Fatalf("Failed to umarshal %#v: %v", byts, err)
	}
	return e
}
