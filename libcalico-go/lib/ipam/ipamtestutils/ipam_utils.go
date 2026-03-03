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

package ipamtestutils

import (
	"context"
	"fmt"
	"sort"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// Pool holds test configuration for an IP pool.
type Pool struct {
	CIDR              string
	BlockSize         int
	Enabled           bool
	NodeSelector      string
	NamespaceSelector string
	AllowedUses       []v3.IPPoolAllowedUse
	AssignmentMode    v3.AssignmentMode
}

// IPPoolAccessor is a mock IP pool accessor for IPAM tests.
type IPPoolAccessor struct {
	Pools map[string]Pool
}

func (i *IPPoolAccessor) GetAllPools(ctx context.Context) ([]v3.IPPool, error) {
	poolNames := make([]string, 0)
	for p := range i.Pools {
		poolNames = append(poolNames, p)
	}
	return i.getPools(poolNames, 0, "GetAllPools"), nil
}

func (i *IPPoolAccessor) GetEnabledPools(ctx context.Context, ipVersion int) ([]v3.IPPool, error) {
	poolNames := make([]string, 0)
	for p, e := range i.Pools {
		if e.Enabled {
			poolNames = append(poolNames, p)
		}
	}
	return i.getPools(poolNames, ipVersion, "GetEnabledPools"), nil
}

func (i *IPPoolAccessor) getPools(poolNames []string, ipVersion int, caller string) []v3.IPPool {
	sort.Strings(poolNames)

	pools := make([]v3.IPPool, 0)
	automatic := v3.Automatic
	var poolsToPrint []string
	for _, p := range poolNames {
		c := cnet.MustParseCIDR(p)
		if (ipVersion == 0) || (c.Version() == ipVersion) {
			pool := v3.IPPool{Spec: v3.IPPoolSpec{
				CIDR:              p,
				NodeSelector:      i.Pools[p].NodeSelector,
				NamespaceSelector: i.Pools[p].NamespaceSelector,
				AllowedUses:       i.Pools[p].AllowedUses,
				AssignmentMode:    &automatic,
			}}
			if len(pool.Spec.AllowedUses) == 0 {
				pool.Spec.AllowedUses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel}
			}
			if i.Pools[p].BlockSize == 0 {
				if c.Version() == 4 {
					pool.Spec.BlockSize = 26
				} else {
					pool.Spec.BlockSize = 122
				}
			} else {
				pool.Spec.BlockSize = i.Pools[p].BlockSize
			}
			pools = append(pools, pool)

			poolsToPrint = append(poolsToPrint, fmt.Sprintf("{%s(%v) %q %v}",
				p, pool.Spec.BlockSize, pool.Spec.NodeSelector, i.Pools[p].AllowedUses))
		}
	}

	log.Debugf("Mock %v returns: %v", caller, poolsToPrint)

	return pools
}

// FakeReservations is a mock IP reservation lister that returns no reservations.
type FakeReservations struct {
	Reservations []v3.IPReservation
}

func (f *FakeReservations) List(ctx context.Context, opts options.ListOptions) (*v3.IPReservationList, error) {
	return &v3.IPReservationList{Items: f.Reservations}, nil
}

// ApplyNode creates or updates a node in the backend for tests.
func ApplyNode(c bapi.Client, kc *kubernetes.Clientset, host string, labels map[string]string) {
	ExpectWithOffset(1, TryApplyNode(c, kc, host, labels)).NotTo(HaveOccurred())
}

// TryApplyNode creates or updates a node, returning any error.
func TryApplyNode(c bapi.Client, kc *kubernetes.Clientset, host string, labels map[string]string) error {
	if kc != nil {
		n := corev1.Node{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Node",
				APIVersion: "v1",
			},
		}
		n.Name = host
		n.Labels = labels

		_, err := kc.CoreV1().Nodes().Create(context.Background(), &n, metav1.CreateOptions{})
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				oldNode, _ := kc.CoreV1().Nodes().Get(context.Background(), host, metav1.GetOptions{})
				oldNode.Labels = labels
				_, err = kc.CoreV1().Nodes().Update(context.Background(), oldNode, metav1.UpdateOptions{})
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}
		log.WithField("node", host).WithError(err).Info("node applied")
	} else {
		_, err := c.Apply(context.Background(), &model.KVPair{
			Key: model.ResourceKey{Name: host, Kind: internalapi.KindNode},
			Value: internalapi.Node{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: internalapi.NodeSpec{OrchRefs: []internalapi.OrchRef{
					{NodeName: host, Orchestrator: "k8s"},
				}},
			},
		})
		if err != nil {
			return err
		}
	}
	return nil
}
