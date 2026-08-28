// Copyright (c) 2022-2024 Tigera, Inc. All rights reserved.

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

package crypto

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestGeneratePassword(t *testing.T) {
	RegisterTestingT(t)

	t.Log("Testing GeneratePassword generates correct lengths...")
	for l := 0; l < 100; l++ {
		p := GeneratePassword(l)
		Expect(p).To(HaveLen(l), "GeneratePassword returned result with incorrect length")
	}

	t.Log("Testing GeneratePassword doesn't generate dupes...")
	seenPasswords := map[string]bool{}
	seenChars := map[rune]bool{}
	for i := 0; i < 1000; i++ {
		p := GeneratePassword(22) // 132 bits of entropy, vanishingly unlikely to see dupes by chance
		Expect(seenPasswords).NotTo(HaveKey(p), "GeneratePassword generated duplicate passwords")
		seenPasswords[p] = true
		for _, r := range p {
			seenChars[r] = true
		}
	}
	Expect(seenChars).To(HaveLen(len(chars)), "GeneratePassword didn't use every character after many trials")
}
