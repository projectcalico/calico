// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package _chan_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestChan(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Chan Suite")
}
