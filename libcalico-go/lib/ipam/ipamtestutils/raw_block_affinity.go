// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package ipamtestutils

import (
	"context"
	"fmt"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

// CreateUnlabeledBlockAffinity creates a BlockAffinty directly using the
// controller-runtime client. It doesn't add the usual labels that KDD would
// add. Useful for testing that upgrade correctly adds the labels.
func CreateUnlabeledBlockAffinity(ctx context.Context, cclient crclient.Client, host string, cidr string) error {
	_, ipn, err := cnet.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s", host, names.CIDRToName(*ipn))

	// Determine which API group to use.
	cfg, err := apiconfig.LoadClientConfig("")
	if err != nil {
		return err
	}
	v3CRD := k8s.UsingV3CRDs(&cfg.Spec)

	if !v3CRD {
		// Use the crd.projectcalico.org/v1 API group.
		ba := &libapiv3.BlockAffinity{
			TypeMeta: metav1.TypeMeta{
				Kind:       libapiv3.KindBlockAffinity,
				APIVersion: "crd.projectcalico.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: libapiv3.BlockAffinitySpec{
				State:   string(apiv3.StateConfirmed),
				Node:    host,
				Type:    "host",
				CIDR:    cidr,
				Deleted: "false",
			},
		}
		return cclient.Create(ctx, ba)
	}

	// Use the projectcalico.org/v3 API group.
	ba := &apiv3.BlockAffinity{
		TypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindBlockAffinity,
			APIVersion: "projectcalico.org/v3",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: apiv3.BlockAffinitySpec{
			State:   apiv3.StateConfirmed,
			Node:    host,
			Type:    "host",
			CIDR:    cidr,
			Deleted: false,
		},
	}
	return cclient.Create(ctx, ba)
}
