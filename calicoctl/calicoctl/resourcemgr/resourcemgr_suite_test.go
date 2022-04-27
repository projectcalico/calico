// Copyright (c) 2016-2018 Tigera, Inc. All rights reserved.

package resourcemgr_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"

)

func TestResourcemgr(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resourcemgr Suite")
}
