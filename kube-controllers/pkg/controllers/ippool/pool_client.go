// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package ippool

import (
	"context"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// poolClient writes IPPools to the API group that backs the cluster.
type poolClient interface {
	Update(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error)
	UpdateStatus(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error)
}

var (
	_ poolClient = &v3PoolClient{}
	_ poolClient = &datastorePoolClient{}
)

// v3PoolClient writes projectcalico.org/v3 IPPools directly.
type v3PoolClient struct {
	cli clientset.Interface
}

func (c *v3PoolClient) Update(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error) {
	return c.cli.ProjectcalicoV3().IPPools().Update(ctx, p, metav1.UpdateOptions{})
}

func (c *v3PoolClient) UpdateStatus(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error) {
	return c.cli.ProjectcalicoV3().IPPools().UpdateStatus(ctx, p, metav1.UpdateOptions{})
}

// datastorePoolClient writes through libcalico, which targets crd.projectcalico.org/v1 without going through the Calico API server.
type datastorePoolClient struct {
	cli client.Interface
}

func (c *datastorePoolClient) Update(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error) {
	return c.cli.IPPools().Update(ctx, p, options.SetOptions{})
}

func (c *datastorePoolClient) UpdateStatus(ctx context.Context, p *v3.IPPool) (*v3.IPPool, error) {
	return c.cli.IPPools().UpdateStatus(ctx, p, options.SetOptions{})
}
