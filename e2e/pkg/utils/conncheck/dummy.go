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

package conncheck

import (
	"time"

	"github.com/onsi/ginkgo/v2"
)

type DummyConnectionTester struct{}

func NewDummyConnectionTester() ConnectionTester {
	return &DummyConnectionTester{}
}

func (d *DummyConnectionTester) Stop() {
}

func (d *DummyConnectionTester) AddClient(_ Client) {
	ginkgo.Fail("Unexpected AddClient call", 1)
}

func (d *DummyConnectionTester) AddServer(_ Server) {
	ginkgo.Fail("Unexpected AddServer call", 1)
}

func (d *DummyConnectionTester) Deploy() {
	ginkgo.Fail("Unexpected Deploy call", 1)
}

func (d *DummyConnectionTester) StopClient(_ Client) {
	ginkgo.Fail("Unexpected StopClient call", 1)
}

func (d *DummyConnectionTester) ExpectSuccess(_ Client, _ ...Target) {
	ginkgo.Fail("Unexpected ExpectSuccess call", 1)
}

func (d *DummyConnectionTester) ExpectFailure(_ Client, _ ...Target) {
	ginkgo.Fail("Unexpected ExpectFailure call", 1)
}

func (d *DummyConnectionTester) Execute() {
	ginkgo.Fail("Unexpected Execute call", 1)
}

func (d *DummyConnectionTester) ResetExpectations() {
	ginkgo.Fail("Unexpected ResetExpectations call", 1)
}

func (d *DummyConnectionTester) WithTimeout(_ time.Duration) {
	ginkgo.Fail("Unexpected WithTimeout call", 1)
}

func (d *DummyConnectionTester) ExpectContinuously(_ Client, _ ...Target) Checkpointer {
	ginkgo.Fail("Unexpected ExpectContinuously call", 1)
	return nil
}

func (d *DummyConnectionTester) Connect(_ Client, _ Target) (string, error) {
	ginkgo.Fail("Unexpected Connect call", 1)
	return "", nil
}

func (d *DummyConnectionTester) ExpectEncrypted(_ Client, _ Target) {
	ginkgo.Fail("Unexpected ExpectEncrypted call", 1)
}

func (d *DummyConnectionTester) ExpectPlaintext(_ Client, _ Target) {
	ginkgo.Fail("Unexpected ExpectPlaintext call", 1)
}
