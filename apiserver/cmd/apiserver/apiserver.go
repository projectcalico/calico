// Copyright (c) 2021-2025 Tigera, Inc. All rights reserved.

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

	"k8s.io/apiserver/pkg/features"
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/component-base/cli"
	"k8s.io/component-base/logs"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
	"github.com/projectcalico/calico/lib/std/log"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	err := feature.DefaultMutableFeatureGate.SetFromMap(map[string]bool{
		// The ConsistentListFromCache feature gate requires our resourceStore
		// to support method RequestWatchProgress, which it does not.  Force-disable
		// the gate.
		string(features.ConsistentListFromCache): false,

		// WatchList requires watch bookmarks, which our API server does not currently support.
		// Note that the WatchBookmarks feature is required to be true - we should probably add
		// support for this!
		string(features.WatchList): false,
	})
	if err != nil {
		log.Errorf("Error setting feature gates: %v.", err)
		logs.FlushLogs()
		os.Exit(1)
	}

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	buildinfo.PrintVersion()

	cmd, _, err := server.NewCommandStartCalicoServer(os.Stdout)
	if err != nil {
		log.Errorf("Error creating server: %v", err)
		logs.FlushLogs()
		os.Exit(1)
	}

	code := cli.Run(cmd)
	os.Exit(code)
}
