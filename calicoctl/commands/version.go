// Copyright (c) 2016-2021 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/docopt/docopt-go"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/libcalico-go/lib/options"

	"github.com/projectcalico/calicoctl/v3/calicoctl/commands/argutils"
	"github.com/projectcalico/calicoctl/v3/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calicoctl/v3/calicoctl/commands/constants"
	"github.com/projectcalico/calicoctl/v3/calicoctl/util"
)

var VERSION, GIT_REVISION string
var VERSION_SUMMARY string

func init() {
	name, _ := util.NameAndDescription()
	VERSION_SUMMARY = strings.ReplaceAll(`Run '<BINARY_NAME> version' to see version information.`, "<BINARY_NAME>", name)
}

func Version(args []string) error {
	doc := `Usage:
  <BINARY_NAME> version [--config=<CONFIG>] [--poll=<POLL>]

Options:
  -h --help             Show this screen.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: ` + constants.DefaultConfigPath + `]
     --poll=<POLL>      Poll for changes to the cluster information at a frequency specified using POLL duration
                        (e.g. 1s, 10m, 2h etc.). A value of 0 (the default) disables polling.

Description:
  Display the version of <BINARY_NAME>.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("Invalid option: 'calicoctl %s'. Use flag '--help' to read about a specific subcommand.", strings.Join(args, " "))
	}
	if len(parsedArgs) == 0 {
		return nil
	}

	// Parse the poll duration.
	var pollDuration time.Duration
	var ci *v3.ClusterInformation
	if poll := argutils.ArgStringOrBlank(parsedArgs, "--poll"); poll != "" {
		if pollDuration, err = time.ParseDuration(poll); err != nil {
			return fmt.Errorf("Invalid poll duration specified: %s", pollDuration)
		}
	}

	fmt.Println("Client Version:   ", VERSION)
	fmt.Println("Git commit:       ", GIT_REVISION)

	// Load the client config and connect.
	cf := parsedArgs["--config"].(string)
	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var pv, pt string

	for {
		if ci, err = client.ClusterInformation().Get(ctx, "default", options.GetOptions{}); err == nil {
			v := ci.Spec.CalicoVersion
			if v == "" {
				v = "unknown"
			}
			t := ci.Spec.ClusterType
			if t == "" {
				t = "unknown"
			}

			if pv != v {
				fmt.Println("Cluster Version:  ", v)
				pv = v
			}
			if pt != t {
				fmt.Println("Cluster Type:     ", t)
				pt = t
			}
		} else {
			// Unable to retrieve the version.  Reset the old versions so that we re-display when we are able to
			// determine the version again (if polling).
			err = fmt.Errorf("Unable to retrieve Cluster Version or Type: %s", err)
			pv = ""
			pt = ""
		}

		if pollDuration == 0 {
			// We are not polling, so exit.
			break
		}

		// We are polling, so display any error that we encountered determining the version and then wait for the next
		// iteration.
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		time.Sleep(pollDuration)
	}

	return err
}

func VersionMismatch(args []string) error {
	// We need to "look ahead" to see if config or context have been passed in the args
	doc := `Usage:
  <BINARY_NAME> [options] [<args>...]

Options:
  -h --help                 Show this screen.
  -c --config=<config>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: ` + constants.DefaultConfigPath + `]
  --context=<context>       The name of the kubeconfig context to use.
  -a
  -A --all-namespaces
     --as=<AS_NUM>
     --backend=(bird|gobgp|none)
     --dryrun
     --export
     --felix-config=<CONFIG>
  -f --filename=<FILENAME>
     --force
     --from-report=<REPORT>
     --ignore-validation
     --init-system
     --ip6-autodetection-method=<IP6_AUTODETECTION_METHOD>
     --ip6=<IP6>
     --ip-autodetection-method=<IP_AUTODETECTION_METHOD>
     --ip=<IP>
     --kernel-config=<kernel-config>
     --log-dir=<LOG_DIR>
     --name=<NAME>
  -n --namespace=<NS>
     --no-default-ippools
     --node-image=<DOCKER_IMAGE_NAME>
  -o --output=<OUTPUT FORMAT>
     --overwrite
     --poll=<POLL>
  -p --patch=<PATCH>
     --remove
  -R --recursive
     --show-all-ips
     --show-blocks
     --show-borrowed
     --show-configuration
     --show-problem-ips
     --skip-empty
     --skip-exists
  -s --skip-not-exists
     --strictaffinity=<true/false>
  -t --type=<TYPE>

Description:
  This is an intermediate parser for version mismatch verification and should
  contain every command line option used everywhere in <BINARY_NAME>. If there
  is an error at this point, there probably is some command line option that
  should be added to this docstring.
`
	// Replace all instances of BINARY_NAME with the name of the binary.
	name, _ := util.NameAndDescription()
	doc = strings.ReplaceAll(doc, "<BINARY_NAME>", name)

	parsedArgs, err := docopt.ParseArgs(doc, args, "")
	if err != nil {
		return fmt.Errorf("docopts parsing for version mismatch verification error: %w", err)
	}

	if context := parsedArgs["--context"]; context != nil {
		os.Setenv("K8S_CURRENT_CONTEXT", context.(string))
	}

	cf, _ := parsedArgs["--config"].(string)

	client, err := clientmgr.NewClient(cf)
	if err != nil {
		return fmt.Errorf("Unable to create Calico API client to verify version mismatch: %w", err)
	}

	ctx := context.Background()

	ci, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to get Cluster Information to verify version mismatch: %w", err)
	}

	clusterv := ci.Spec.CalicoVersion
	if clusterv == "" {
		// CalicoVersion field not specified in the cluster, so skip check.
		return nil
	} else {
		clusterv = strings.Split(clusterv, "-")[0]
	}

	clientv := strings.Split(VERSION, "-")[0]

	if clusterv != clientv {
		return fmt.Errorf("Version mismatch.\nClient Version:   %s\nCluster Version:  %s", VERSION, clusterv)
	}

	return nil
}
