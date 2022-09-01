// Copyright (c) 2022 Tigera, Inc. All rights reserved.

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

package utils

import (
	"os"

	. "github.com/onsi/gomega"
)

func PatchEnv(key, value string) (unpatch func(), err error) {
	oldKC, oldKCSet := os.LookupEnv(key)
	err = os.Setenv(key, value)
	if err != nil {
		return
	}
	if oldKCSet {
		unpatch = func() {
			Expect(os.Setenv(key, oldKC)).NotTo(HaveOccurred())
		}
	} else {
		unpatch = func() {
			Expect(os.Unsetenv(key)).NotTo(HaveOccurred())
		}
	}
	return
}
