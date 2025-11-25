// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package types

import (
	"fmt"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

type PolicyID struct {
	Name      string
	Namespace string
	Kind      string
}

func (p PolicyID) String() string {
	return fmt.Sprintf("{Name: %s, Namespace: %s, Kind: %s}", p.Name, p.Namespace, p.Kind)
}

func (p PolicyID) ID() string {
	// Include namespace only if it's set.
	if p.Namespace != "" {
		return fmt.Sprintf("%s/%s/%s", p.KindShortName(), p.Namespace, p.Name)
	}
	return fmt.Sprintf("%s/%s", p.KindShortName(), p.Name)
}

// KindShortName returns a short string for the kind of policy. This is used where space is at a premium,
// e.g. in NFLOG prefixes. If the kind is unrecognized, it returns the full kind string.
func (p PolicyID) KindShortName() string {
	switch p.Kind {
	case v3.KindNetworkPolicy:
		return "np"
	case v3.KindGlobalNetworkPolicy:
		return "gnp"
	case v3.KindStagedNetworkPolicy:
		return "snp"
	case v3.KindStagedGlobalNetworkPolicy:
		return "sgnp"
	case v3.KindStagedKubernetesNetworkPolicy:
		return "sknp"
	case model.KindKubernetesNetworkPolicy:
		return "knp"
	case model.KindKubernetesClusterNetworkPolicy:
		return "kcnp"
	default:
		logrus.Warnf("Unrecognized policy kind %q when generating short name", p.Kind)
		return p.Kind
	}
}

func ProtoToPolicyID(p *proto.PolicyID) PolicyID {
	return PolicyID{
		Name:      p.GetName(),
		Namespace: p.GetNamespace(),
		Kind:      p.GetKind(),
	}
}

func PolicyIDToProto(p PolicyID) *proto.PolicyID {
	return &proto.PolicyID{
		Name:      p.Name,
		Namespace: p.Namespace,
		Kind:      p.Kind,
	}
}
