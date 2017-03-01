// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package throttle

type Throttle struct {
	bucketSize int
	count      int
}

func New(bucketSize int) *Throttle {
	return &Throttle{
		bucketSize: bucketSize,
	}
}

func (t *Throttle) Refill() {
	if t.count >= t.bucketSize {
		return
	}
	t.count += 1
}

func (t *Throttle) Admit() bool {
	if t.count <= 0 {
		return false
	}
	t.count--
	return true
}

func (t *Throttle) WouldAdmit() bool {
	return t.count > 0
}
