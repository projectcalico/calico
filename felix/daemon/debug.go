// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package daemon

import (
	"time"

	log "github.com/sirupsen/logrus"
)

func panicAfter(delay time.Duration) {
	time.Sleep(delay)
	log.Panic("Panicking because config told me to!")
}

func simulateDataRace() {
	i := 0
	for j := 0; j < 3; j++ {
		go func() {
			for {
				k := i
				time.Sleep(1 * time.Millisecond)
				i = k + 1
			}
		}()
	}
}
