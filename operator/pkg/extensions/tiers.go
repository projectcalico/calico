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

package extensions

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
)

// TiersExtension is the variant's hook into the tiers controller.
type TiersExtension interface {
	// Watches registers the variant's watches.
	Watches(c ctrlruntime.Controller) error

	// DNSClientNamespaces are the variant's namespaces that run product code and so
	// need access to the DNS service.
	DNSClientNamespaces(ctx context.Context, cli client.Client) ([]string, error)
}

// noopTiers runs the core operator's behavior unchanged.
type noopTiers struct{}

func (noopTiers) Watches(ctrlruntime.Controller) error {
	return nil
}

func (noopTiers) DNSClientNamespaces(context.Context, client.Client) ([]string, error) {
	return nil, nil
}
