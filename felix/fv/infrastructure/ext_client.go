// Copyright (c) 2022  All rights reserved.

package infrastructure

import (
	"os"

	. "github.com/onsi/gomega"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/felix/fv/utils"
)

func RunExtClient() *containers.Container {
	wd, err := os.Getwd()
	Expect(err).NotTo(HaveOccurred(), "failed to get working directory")
	externalClient := containers.Run(
		"external-client",
		containers.RunOpts{
			AutoRemove: true,
		},
		"--privileged",                    // So that we can add routes inside the container.
		"-v", wd+"/../bin:/usr/local/bin", // Map in the test-connectivity binary etc.
		utils.Config.BusyboxImage,
		"/bin/sh", "-c", "sleep 1000")
	return externalClient
}
