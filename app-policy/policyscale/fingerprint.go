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

package policyscale

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// FingerprintAnnotation is the annotation on every rendered tier that holds Fingerprint of the
// fixture the resources came from.
const FingerprintAnnotation = "policyscale.projectcalico.org/fixture"

// Fingerprint identifies the policy set a Spec builds: Specs with equal fingerprints build the same
// fixture. A tool that sends traffic at a cluster compares its own fingerprint with the one on the
// applied tiers, because flows drawn from a different fixture aim at destinations no applied rule
// carries, and every one of them misses.
func Fingerprint(spec Spec) string {
	b, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}
