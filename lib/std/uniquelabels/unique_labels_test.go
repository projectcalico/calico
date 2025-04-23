// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package uniquelabels

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestInternedLabelsJSONRoundTrip(t *testing.T) {
	m := map[string]string{"foo": "bar", "bar": "baz"}
	j, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	in := Make(m)
	j2, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(j, j2) {
		t.Errorf("Interned map should produce same JSON as normal map; got %s, want %s", j2, j)
	}

	var out Map
	err = json.Unmarshal(j2, &out)
	if err != nil {
		t.Fatal(err)
	}
	if !in.Equals(out) {
		t.Errorf("Interned map didn't round trip. Got %v, want %v", out, in)
	}
}
