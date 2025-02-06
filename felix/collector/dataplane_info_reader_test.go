// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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
