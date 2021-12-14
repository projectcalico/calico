// Copyright (c) 2017 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"time"

	"github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/iptables"
)

const usage = `iptables-locker, test tool for grabbing the iptables lock.

Usage:
  iptables-locker <duration>

`

func main() {
	arguments, err := docopt.ParseArgs(usage, nil, "v0.1")
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}
	durationStr := arguments["<duration>"].(string)
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		println(usage)
		log.WithError(err).Fatal("Failed to parse usage")
	}

	iptablesLock := iptables.NewSharedLock(
		"/run/xtables.lock",
		1*time.Second,
		50*time.Millisecond,
	)
	iptablesLock.Lock()
	println("LOCKED")
	time.Sleep(duration)
	iptablesLock.Unlock()
}
