// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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
	"flag"
	"fmt"
	"os"

	confdConfig "github.com/kelseyhightower/confd/pkg/config"
	confd "github.com/kelseyhightower/confd/pkg/run"
	felix "github.com/projectcalico/felix/daemon"

	"github.com/projectcalico/node/pkg/allocateipip"
	"github.com/projectcalico/node/pkg/readiness"
	"github.com/projectcalico/node/pkg/startup"

	"github.com/projectcalico/libcalico-go/lib/logutils"
	"github.com/sirupsen/logrus"
)

// Populated by build - used for printing version.
var VERSION string

// Create a new flag set.
var flagSet = flag.NewFlagSet("Calico", flag.ContinueOnError)

// Build the set of supported flags.
var version = flagSet.Bool("v", false, "Display version")
var runFelix = flagSet.Bool("felix", false, "Run Felix")
var runStartup = flagSet.Bool("startup", false, "Initialize a new node")
var runAllocateIPIP = flagSet.Bool("allocate-ipip-addr", false, "Allocate an IPIP address for this node")

// Options for readiness checks.
var birdReady = flagSet.Bool("bird-ready", false, "Run BIRD readiness checks")
var bird6Ready = flagSet.Bool("bird6-ready", false, "Run BIRD6 readiness checks")
var felixReady = flagSet.Bool("felix-ready", false, "Run felix readiness checks")

// confd flags
var runConfd = flagSet.Bool("confd", false, "Run confd")
var confdRunOnce = flagSet.Bool("confd-run-once", false, "Run confd in oneshot mode")
var confdKeep = flagSet.Bool("confd-keep-stage-file", false, "Keep stage file when running confd")

func main() {
	// Set up logging formatting.
	logrus.SetFormatter(&logutils.Formatter{})

	// Install a hook that adds file/line no information.
	logrus.AddHook(&logutils.ContextHook{})

	// Parse the provided flags.
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Perform some validation on the parsed flags. Only one of the following may be
	// specified at a time.
	onlyOne := []*bool{version, runFelix, runStartup, runConfd}
	oneSelected := false
	for _, o := range onlyOne {
		if oneSelected && *o {
			fmt.Println("More than one incompatible argument provided")
			os.Exit(1)
		}

		if *o {
			oneSelected = true
		}
	}

	// If any of the readienss options are provided, check readiness.
	if *birdReady || *bird6Ready || *felixReady {
		readiness.Run(*birdReady, *bird6Ready, *felixReady)
		os.Exit(0)
	}

	// Decide which action to take based on the given flags.
	if *version {
		fmt.Println(VERSION)
		os.Exit(0)
	} else if *runFelix {
		felix.Run("/etc/calico/felix.cfg")
	} else if *runStartup {
		startup.Run()
	} else if *runConfd {
		cfg, err := confdConfig.InitConfig(true)
		cfg.ConfDir = "/etc/calico/confd"
		cfg.KeepStageFile = *confdKeep
		cfg.Onetime = *confdRunOnce
		if err != nil {
			panic(err)
		}
		confd.Run(cfg)
	} else if *runAllocateIPIP {
		allocateipip.Run()
	} else {
		fmt.Println("No valid options provided. Usage:")
		flagSet.PrintDefaults()
		os.Exit(1)
	}
}
