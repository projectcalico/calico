//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/testutils"

	"testing"
)

func init() {
	testutils.HookLogrusForGinkgo()
}

func TestCalicoCni(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "CNI suite")
}
