// Copyright (c) 2021 Tigera, Inc. All rights reserved.

/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"os"
	"runtime"

	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/projectcalico/calico/libcalico-go/lib/seedrng"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
)

func main() {
	// Make sure the RNG is seeded.
	seedrng.EnsureSeeded()

	logs.InitLogs()
	defer logs.FlushLogs()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	err := server.Version()
	if err != nil {
		klog.Errorf("Error printing version info.")
		logs.FlushLogs()
	}

	cmd, err := server.NewCommandStartCalicoServer(os.Stdout)
	if err != nil {
		klog.Errorf("Error creating server: %v", err)
		logs.FlushLogs()
		os.Exit(1)
	}

	if err := cmd.Execute(); err != nil {
		klog.Errorf("server exited unexpectedly (%s)", err)
		logs.FlushLogs()
		os.Exit(1)
	}
}
