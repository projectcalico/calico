// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

package collector

import (
	"testing"
	"time"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
)

func TestRun(t *testing.T) {
	g := NewGomegaWithT(t)

	infoC := make(chan interface{})
	dpr := NewDataplaneInfoReader(infoC)

	// Start the reader
	err := dpr.Start()
	g.Expect(err).NotTo(HaveOccurred())

	// Send some data to the infoC channel
	info := &proto.NamespaceUpdate{
		Id: &proto.NamespaceID{
			Name: "test",
		},
		Labels: map[string]string{},
	}
	infoC <- info

	// Check that the data is received on the dataplaneInfoC channel
	g.Eventually(dpr.DataplaneInfoChan(), 1000*time.Second).Should(Receive())

	// Stop the reader
	dpr.Stop()

	// Check that the reader has stopped
	g.Expect(dpr.stopC).To(BeClosed())
}
