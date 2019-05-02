// Copyright (c) 2016-2019 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calicoctl/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/calicoctl/commands/constants"

	log "github.com/sirupsen/logrus"
)

func Get(args []string) error {
	doc := constants.DatastoreIntro + `Usage:
  calicoctl get ( (<KIND> [<NAME>...]) |
                --filename=<FILENAME>)
                [--output=<OUTPUT>] [--config=<CONFIG>] [--namespace=<NS>] [--all-namespaces] [--export]

Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List a specific policies in YAML format
  calicoctl get -o yaml policy my-policy-1 my-policy-2

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to
                               "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json, ps, wide,
                               custom-columns=..., go-template=...,
                               go-template-file=...   [Default: ps]
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                               Uses the default namespace if not specified.
  -a --all-namespaces          If present, list the requested object(s) across all namespaces.
  --export                     If present, returns the requested object(s) stripped of
                               cluster-specific information. This flag will be ignored
			       if <NAME> is not specified.

Description:
  The get command is used to display a set of resources by filename or stdin,
  or by type and identifiers.  JSON and YAML formats are accepted for file and
  stdin format.

  Valid resource types are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * globalNetworkSet
    * hostEndpoint
    * ipPool
    * networkPolicy
    * networkSet
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to get resources that do not exist will simply return no results.

  When getting resources by type, only a single type may be specified at a
  time.  The name and other identifiers (hostname, scope) are optional, and are
  wildcarded when omitted. Thus if you specify no identifiers at all (other
  than type), then all configured resources of the requested type will be
  returned.

  By default the results are output in a ps-style table output.  There are
  alternative ways to display the data using the --output option:

    ps                    Display the results in ps-style output.
    wide                  As per the ps option, but includes more headings.
    custom-columns        As per the ps option, but only display the columns
                          that are requested in the comma-separated list.
    go-template           Display the results using the specified golang
                          template.  This can be used to filter results, for
                          example to return a specific value.
    go-template-file      Display the results using the golang template that is
                          contained in the specified file.
    yaml                  Display the results in YAML output format.
    json                  Display the results in JSON output format.

  Note that the data output using YAML or JSON format is always valid to use as
  input to all of the resource management commands (create, apply, replace,
  delete, get).

  Please refer to the docs at https://docs.projectcalico.org for more details on
  the output formats, including example outputs, resource structure (required
  for the golang template definitions) and the valid column names (required for
  the custom-columns option).
`
	parsedArgs, err := docopt.Parse(doc, args, true, "", false, false)
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	printNamespace := false
	if argutils.ArgBoolOrFalse(parsedArgs, "--all-namespaces") || argutils.ArgStringOrBlank(parsedArgs, "--namespace") != "" {
		printNamespace = true
	}

	var rp resourcePrinter
	output := parsedArgs["--output"].(string)
	switch output {
	case "yaml", "yml":
		rp = resourcePrinterYAML{}
	case "json":
		rp = resourcePrinterJSON{}
	case "ps":
		rp = resourcePrinterTable{wide: false, printNamespace: printNamespace}
	case "wide":
		rp = resourcePrinterTable{wide: true, printNamespace: printNamespace}
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

	results := executeConfigCommand(parsedArgs, actionGetOrList)

	log.Infof("results: %+v", results)

	if results.fileInvalid {
		return fmt.Errorf("Failed to execute command: %v", results.err)
	} else if results.err != nil {
		return fmt.Errorf("Failed to get resources: %v", results.err)
	}

	err = rp.print(results.client, results.resources)
	if err != nil {
		return err
	}

	if len(results.resErrs) > 0 {
		var errStr string
		for _, err := range results.resErrs {
			errStr += err.Error()
		}
		return fmt.Errorf(errStr)
	}

	return nil
}
