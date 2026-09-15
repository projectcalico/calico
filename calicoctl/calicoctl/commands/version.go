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
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/constants"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/pkg/buildinfo"
)

// runVersion prints the client version and, unless clientOnly is set, the
// cluster version. A non-empty poll duration re-displays the cluster version
// on that interval. Version mismatch is intentionally never enforced here.
func runVersion(configPath, poll string, clientOnly bool) error {
	var pollDuration time.Duration
	if poll != "" {
		var err error
		if pollDuration, err = time.ParseDuration(poll); err != nil {
			return fmt.Errorf("invalid poll duration specified: %s", poll)
		}
	}

	fmt.Println("Client Version:   ", buildinfo.Version)
	fmt.Println("Git commit:       ", buildinfo.GitRevision)

	if clientOnly {
		return nil
	}

	if configPath == "" {
		configPath = constants.DefaultConfigPath
	}
	client, err := clientmgr.NewClient(configPath)
	if err != nil {
		if derr, ok := err.(errors.ErrorDatastoreError); ok {
			logrus.Debugf("Client config error: %s", derr.Error())
			fmt.Println("Unable to detect installed Calico version")
			return nil
		}
		return err
	}
	ctx := context.Background()
	var pv, pt string
	var ci *v3.ClusterInformation

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
			err = fmt.Errorf("unable to retrieve Cluster Version or Type: %s", err)
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
