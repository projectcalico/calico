// Copyright (c) 2020 Tigera, Inc. All rights reserved.
package main

import (
	"os"
)

func main() {
	// File to  check for apiserver is ready for readiness probe. This path should
	// match with code in apiserver. [function RunServer]
	fPath := "/tmp/ready"
	// Check for ready file created by apiserver
	// if file is present return zero else non-zero value
	_, ok := os.Stat(fPath)

	if ok != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
