// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package policystore

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestReadBlocksWrite(t *testing.T) {
	RegisterTestingT(t)
	until := make(chan bool)
	readStep := make(chan bool)
	writeStep := make(chan bool)

	readBlocker := func(store *PolicyStore) {
		readStep <- true
		<-until
	}

	writer := func(store *PolicyStore) {
		writeStep <- true
	}
	store := NewPolicyStore()
	go store.Read(readBlocker)
	<-readStep
	go store.Write(writer)
	// writer should be blocked by reader.
	Eventually(writeStep).ShouldNot(Receive())
	until <- true
	Eventually(writeStep).Should(Receive())
}

func TestReadAllowsRead(t *testing.T) {
	RegisterTestingT(t)
	until := make(chan bool)
	read1Step := make(chan bool)
	read2Step := make(chan bool)

	read1 := func(store *PolicyStore) {
		read1Step <- true
		<-until
	}
	read2 := func(store *PolicyStore) {
		read2Step <- true
	}
	store := NewPolicyStore()
	go store.Read(read1)
	<-read1Step
	go store.Read(read2)
	// Test fails if this blocks, because read1 must be blocking read2.
	Eventually(read2Step).Should(Receive())

	// Clean up so goroutines end
	until <- true
}
