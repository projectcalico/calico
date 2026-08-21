// Copyright (c) 2026 Tigera, Inc. All rights reserved.

package externalnode

import (
	"strings"
	"testing"

	"github.com/onsi/gomega"
)

// The ssh probe returns no addresses when the external node is unreachable, and
// indexing that empty slice used to panic and take the whole Ginkgo node down.
func TestIPWithNoDiscoveredAddressesFails(t *testing.T) {
	gomega.RegisterTestingT(t)
	c := &Client{extIP: "10.0.0.1", intIPs: []string{}}

	err := gomega.InterceptGomegaFailure(func() {
		c.IP()
	})
	if err == nil {
		t.Fatal("expected IP() to fail when no internal IPs were discovered")
	}
	if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Errorf("failure message should name the external node, got: %s", err.Error())
	}
}

func TestIPReturnsFirstDiscoveredAddress(t *testing.T) {
	gomega.RegisterTestingT(t)
	c := &Client{extIP: "10.0.0.1", intIPs: []string{"172.16.0.5", "172.16.0.6"}}

	err := gomega.InterceptGomegaFailure(func() {
		if got := c.IP(); got != "172.16.0.5" {
			t.Errorf("IP() = %s, want 172.16.0.5", got)
		}
	})
	if err != nil {
		t.Fatalf("unexpected failure: %s", err)
	}
}
