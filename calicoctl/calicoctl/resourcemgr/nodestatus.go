// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

func init() {
	registerResource(
		api.NewCalicoNodeStatus(),
		newCalicoNodeStatusList(),
		false,
		[]string{"caliconodestatus", "caliconodestatuses", "nodestatus", "nodestatuses"},
		[]string{"NAME", "NODE"},
		[]string{"NAME", "NODE", "CLASSES"},
		map[string]string{
			"NAME":    "{{.ObjectMeta.Name}}",
			"NODE":    "{{.Spec.Node}}",
			"CLASSES": "{{join .Spec.Classes \",\"}}",
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.CalicoNodeStatus)
			return client.CalicoNodeStatus().Create(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.CalicoNodeStatus)
			return client.CalicoNodeStatus().Update(ctx, r, options.SetOptions{})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.CalicoNodeStatus)
			return client.CalicoNodeStatus().Delete(ctx, r.Name, options.DeleteOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceObject, error) {
			r := resource.(*api.CalicoNodeStatus)
			return client.CalicoNodeStatus().Get(ctx, r.Name, options.GetOptions{ResourceVersion: r.ResourceVersion})
		},
		func(ctx context.Context, client client.Interface, resource ResourceObject) (ResourceListObject, error) {
			r := resource.(*api.CalicoNodeStatus)
			return client.CalicoNodeStatus().List(ctx, options.ListOptions{ResourceVersion: r.ResourceVersion, Name: r.Name})
		},
	)
}

// newCalicoNodeStatusList creates a new (zeroed) CalicoNodeStatusList struct with the
// TypeMetadata initialised to the current version.
func newCalicoNodeStatusList() *api.CalicoNodeStatusList {
	return &api.CalicoNodeStatusList{
		TypeMeta: metav1.TypeMeta{
			Kind:       api.KindCalicoNodeStatusList,
			APIVersion: api.GroupVersionCurrent,
		},
	}
}
