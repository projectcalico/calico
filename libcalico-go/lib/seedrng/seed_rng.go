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

// Package seedrng provides a utility function seedrng.EnsureSeeded() to seed the main math/rand RNG exactly once.
package seedrng

import (
	"math/rand"
	"sync"
	"time"
)

var once sync.Once

// EnsureSeeded seeds the math/rand PRNG on the first call; subsequent calls are no-ops.  This allows EnsureSeeded()
// calls to be sprinkled around the codebase in packages that actively use the PRNG.  That way, we always make
// sure the PRNG is seeded before it is used in anger.
func EnsureSeeded() {
	once.Do(Reseed)
}

func Reseed() {
	rand.Seed(time.Now().UnixNano())
}
