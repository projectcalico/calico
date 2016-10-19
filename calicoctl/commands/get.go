// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package commands

import (
	"github.com/docopt/docopt-go"

	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
)

func Get(args []string) error {
	doc := EtcdIntro + `Display one or many resources identified by file, stdin or resource type and name.

Valid resource kinds are bgpPeer, hostEndpoint, workloadEndpoint, policy, pool and profile.
The <KIND> parameter is case insensitive and may be pluralized.

By specifying the output as 'go-template' and providing a Go template as the value
of the --go-template flag, you can filter the attributes of the fetched resource(s).

Usage:
  calicoctl get ([--node=<NODE>] [--orchestrator=<ORCH>] [--workload=<WORKLOAD>] [--scope=<SCOPE>]
                 (<KIND> [<NAME>]) |
                 --filename=<FILENAME>)
                [--output=<OUTPUT>] [--config=<CONFIG>]

Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List a specific policy in YAML format
  calicoctl get -o yaml policy my-policy-1

Options:
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: ps, wide, custom-columns=..., yaml, json,
                               go-template=..., go-template-file=...   [Default: ps]
  -n --node=<NODE>             The node (this may be the hostname of the compute server if your
                               installation does not explicitly set the names of each Calico node).
     --orchestrator=<ORCH>     The orchestrator (only used for workload endpoints).
     --workload=<WORKLOAD>     The workload (only used for workload endpoints).
  --scope=<SCOPE>              The scope of the resource type.  One of global, node.  This is only valid
                               for BGP peers and is used to indicate whether the peer is a global peer
                               or node-specific.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
`
	parsedArgs, err := docopt.Parse(doc, args, true, "calicoctl", false, false)
	if err != nil {
		return err
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	var rp resourcePrinter
	output := parsedArgs["--output"].(string)
	switch output {
	case "yaml":
		rp = resourcePrinterYAML{}
	case "json":
		rp = resourcePrinterJSON{}
	case "ps":
		rp = resourcePrinterTable{wide: false}
	case "wide":
		rp = resourcePrinterTable{wide: true}
	default:
		// Output format may be a key=value pair, so split on "=" to find out.  Pull
		// out the key and value, and split the value by "," as some options allow
		// a multiple-valued value.
		outputParms := strings.SplitN(output, "=", 2)
		outputKey := outputParms[0]
		outputValue := ""
		outputValues := []string{}
		if len(outputParms) == 2 {
			outputValue = outputParms[1]
			outputValues = strings.Split(outputValue, ",")
		}

		switch outputKey {
		case "go-template":
			if outputValue == "" {
				return fmt.Errorf("need to specify a template")
			}
			rp = resourcePrinterTemplate{template: outputValue}
		case "go-template-file":
			if outputValue == "" {
				return fmt.Errorf("need to specify a template file")
			}
			rp = resourcePrinterTemplateFile{templateFile: outputValue}
		case "custom-columns":
			if outputValue == "" {
				return fmt.Errorf("need to specify at least one column")
			}
			rp = resourcePrinterTable{headings: outputValues}
		}
	}

	if rp == nil {
		return fmt.Errorf("unrecognized output format '%s'", output)
	}

	results := executeConfigCommand(parsedArgs, actionList)
	log.Infof("results: %+v", results)

	if results.err != nil {
		fmt.Printf("Error getting resources: %v\n", results.err)
		return err
	}

	return rp.print(results.resources)
}
