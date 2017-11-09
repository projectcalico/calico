// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package resourcemgr

import (
	"context"

	api "github.com/projectcalico/libcalico-go/lib/apis/v3"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewClusterInformation(),
		api.NewClusterInformationList(),
		false,
		[]string{"clusterinformation", "clusterinformations", "clusterinfo", "clusterinfos"},
		[]string{"NAME", "CLUSTERGUID", "CLUSTERTYPE", "CALICOVERSION", "DATASTOREREADY"},
		[]string{"NAME", "CLUSTERGUID", "CLUSTERTYPE", "CALICOVERSION", "DATASTOREREADY"},
		map[string]string{
			"NAME":           "{{.ObjectMeta.Name}}",
			"CLUSTERGUID":    "{{.Spec.ClusterGUID}}",
			"CLUSTERTYPE":    "{{.Spec.ClusterType}}",
			"CALICOVERSION":  "{{.Spec.CalicoVersion}}",
			"DATASTOREREADY": "{{.Spec.DatastoreReady}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			return nil, cerrors.ErrorOperationNotSupported{
				Operation:  "create or apply",
				Identifier: "ClusterInformation",
			}
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			return nil, cerrors.ErrorOperationNotSupported{
				Operation:  "apply or replace",
				Identifier: "ClusterInformation",
			}
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			return nil, cerrors.ErrorOperationNotSupported{
				Operation:  "delete",
				Identifier: "ClusterInformation",
			}
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.ClusterInformation)
			return client.ClusterInformation().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.ClusterInformation)
			return client.ClusterInformation().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}
