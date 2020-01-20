// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
	"fmt"
	"os"
	"path"
	"sync"

	"github.com/docopt/docopt-go"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/bpf/nat"
	"github.com/projectcalico/felix/bpf/tc"
	"github.com/projectcalico/felix/config"
	"github.com/projectcalico/felix/logutils"
	"github.com/projectcalico/felix/proto"
)

const usage = `Usage:
  compile-bpf 
  compile-bpf gen-makefile-inc
`

func main() {
	logutils.ConfigureEarlyLogging()
	params := &config.Config{LogSeverityScreen: "info"}
	logutils.ConfigureLogging(params)

	opts, err := docopt.ParseDoc(usage)
	if err != nil {
		log.WithError(err).Panic("Failed to parse args")
	}
	generateMakefileInc, _ := opts.Bool("gen-makefile-inc")

	srcDir := "./bpf/tc/templates"
	incDir := "../../include/"
	srcFileName := path.Join(srcDir, "tc_template.c")
	err = os.RemoveAll("bin/bpf")
	if err != nil && !os.IsNotExist(err) {
		log.WithError(err).Panic("Failed to clean up old directory")
	}
	err = os.MkdirAll("bin/bpf", 0755)
	if err != nil {
		log.WithError(err).Panic("Failed to make directory")
	}

	var wg sync.WaitGroup
	for _, logLevel := range []string{"OFF", "INFO", "DEBUG"} {
		logLevel := logLevel
		// Compile the TC endpoint programs.
		logCxt := log.WithField("logLevel", logLevel)
		for _, epToHostDrop := range []bool{false, true} {
			epToHostDrop := epToHostDrop
			logCxt = logCxt.WithField("epToHostDrop", epToHostDrop)
			for _, fibEnabled := range []bool{false, true} {
				fibEnabled := fibEnabled
				logCxt = logCxt.WithField("fibEnabled", fibEnabled)
				for _, epType := range []tc.EndpointType{tc.EpTypeWorkload, tc.EpTypeHost, tc.EpTypeTunnel} {
					epType := epType
					logCxt = logCxt.WithField("epType", epType)
					if epToHostDrop && epType != tc.EpTypeWorkload {
						log.Debug("Skipping combination since epToHostDrop only affect workloads")
						continue
					}
					for _, toOrFrom := range []tc.ToOrFromEp{tc.FromEp, tc.ToEp} {
						toOrFrom := toOrFrom

						logCxt = logCxt.WithField("toOrFrom", toOrFrom)
						if toOrFrom == tc.ToEp && (fibEnabled || epToHostDrop) {
							log.Debug("Skipping combination since fibEnabled/epToHostDrop only affect from targets")
							continue
						}

						secName := tc.SectionName(epType, toOrFrom)
						flags := tc.SectionToFlags(secName)

						oFileName := path.Join("bin/bpf/", tc.ProgFilename(epType, toOrFrom, epToHostDrop, fibEnabled, logLevel))
						if generateMakefileInc {
							fmt.Println("BPF_PROGS +=", oFileName)
							continue
						}

						opts := []tc.CompileOption{
							tc.CompileWithWorkingDir(srcDir),
							tc.CompileWithSourceName(srcFileName),
							tc.CompileWithIncludePath(incDir),
							tc.CompileWithOutputName(oFileName),
							tc.CompileWithFIBEnabled(fibEnabled),
							tc.CompileWithLogLevel(logLevel),
							tc.CompileWithEndpointToHostDrop(epToHostDrop),
							// FIXME CompileWithNATTunnelMTU(uint16(m.natTunnelMTU)),
							tc.CompileWithEntrypointName(secName),
							tc.CompileWithFlags(flags),
							// Special values that we patch when loading the binary.
							tc.CompileWithLogPrefix("CALICOLO"),
						}

						wg.Add(1)
						go func() {
							defer wg.Done()
							var defaultAction = "deny"
							if epType != tc.EpTypeWorkload {
								defaultAction = "allow"
							}
							err := tc.CompileProgramToFile([][][]*proto.Rule{{{{Action: defaultAction}}}}, nil, opts...)
							if err != nil {
								log.WithError(err).Panicf("Failed to compile %s", oFileName)
							}
						}()
					}
				}
			}
		}

		// Compile the connect-time load balancer.
		oFileName := path.Join("bin/bpf/", nat.ProgFileName(logLevel))
		if generateMakefileInc {
			fmt.Println("BPF_PROGS +=", oFileName)
			continue
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := nat.CompileConnectTimeLoadBalancer(logLevel, oFileName)
				if err != nil {
					log.WithError(err).Panicf("Failed to compile %s", oFileName)
				}
			}()
		}
	}

	log.Debug("Waiting for background goroutines to finish...")
	wg.Wait()
	log.Info("Done.")
}
