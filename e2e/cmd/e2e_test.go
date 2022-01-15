package main

import (
	"flag"
	"testing"

	"github.com/onsi/ginkgo"
	"k8s.io/klog"
	"k8s.io/kubernetes/test/e2e"
	"k8s.io/kubernetes/test/e2e/framework"
	"k8s.io/kubernetes/test/e2e/framework/config"

	// Import tests.
	_ "k8s.io/kubernetes/test/e2e/network"
)

func init() {
	klog.SetOutput(ginkgo.GinkgoWriter)

	// Register flags.
	config.CopyFlags(config.Flags, flag.CommandLine)
	framework.RegisterCommonFlags(flag.CommandLine)
	framework.RegisterClusterFlags(flag.CommandLine)

	// Parse all the flags
	flag.Parse()
	framework.AfterReadingAllFlags(&framework.TestContext)
}

func TestE2E(t *testing.T) {
	e2e.RunE2ETests(t)
}
