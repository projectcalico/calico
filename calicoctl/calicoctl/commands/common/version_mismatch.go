// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package common

import (
	"context"
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/clientmgr"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var VERSION string

func CheckVersionMismatch(configArg, allowMismatchArg interface{}) error {
	if allowMismatch, _ := allowMismatchArg.(bool); allowMismatch {
		log.Infof("Skip version mismatch checking due to '--allow-version-mismatch' argument")

		return nil
	}

	cf, _ := configArg.(string)

	client, err := clientmgr.NewClient(cf)
	if err != nil {
		// If we can't connect to the cluster, skip the check. Either we're running a command that
		// doesn't need API access, in which case the check doesn't need to be run, or we'll
		// fail on the actual command.
		log.Infof("Skip version mismatch checking due to not being able to connect to the cluster")

		return nil
	}

	ctx := context.Background()

	ci, err := client.ClusterInformation().Get(ctx, "default", options.GetOptions{})
	if err != nil {
		var notFound cerrors.ErrorResourceDoesNotExist
		if errors.As(err, &notFound) {
			// ClusterInformation does not exist, so skip version check.
			log.Infof("Skip version mismatch checking due to ClusterInformation not being present")

			return nil
		}
		return fmt.Errorf("Unable to get Cluster Information to verify version mismatch: %w\nUse --allow-version-mismatch to override.\n", err)
	}

	clusterv := ci.Spec.CalicoVersion
	if clusterv == "" {
		// CalicoVersion field not specified in the cluster, so skip check.
		log.Infof("Skip version mismatch checking due to CalicoVersion not being set")

		return nil
	}

	clusterv = strings.Split(strings.TrimPrefix(clusterv, "v"), "-")[0]

	clientv := strings.Split(strings.TrimPrefix(VERSION, "v"), "-")[0]

	if clusterv != clientv {
		return fmt.Errorf("Version mismatch.\nClient Version:   %s\nCluster Version:  %s\nUse --allow-version-mismatch to override.\n", VERSION, clusterv)
	}

	return nil
}
