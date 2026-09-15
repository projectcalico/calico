// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.

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

import "sync"

type OnceFlag struct {
	mu   sync.Mutex
	flag bool
}

// TrySet returns true if the flag was false and sets it to true.
// Subsequent calls return false.
func (o *OnceFlag) TrySet() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.flag {
		o.flag = true
		return true
	}
	return false
}

// Reset clears the flag back to false.
func (o *OnceFlag) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.flag = false
}
