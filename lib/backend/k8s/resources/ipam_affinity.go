// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	BlockAffinityResourceName = "BlockAffinities"
	BlockAffinityCRDName      = "blockaffinities.crd.projectcalico.org"
)

func NewAffinityBlockClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customK8sResourceClient{
		clientSet:       c,
		restClient:      r,
		name:            BlockAffinityCRDName,
		resource:        BlockAffinityResourceName,
		description:     "Calico IPAM block affinities",
		k8sResourceType: reflect.TypeOf(apiv3.BlockAffinity{}),
		k8sResourceTypeMeta: metav1.TypeMeta{
			Kind:       apiv3.KindBlockAffinity,
			APIVersion: apiv3.GroupVersionCurrent,
		},
		k8sListType:  reflect.TypeOf(apiv3.BlockAffinityList{}),
		resourceKind: apiv3.KindBlockAffinity,
	}

	return &affinityBlockClient{rc: rc}
}

// Implements the api.Client interface for AffinityBlocks.
type affinityBlockClient struct {
	rc customK8sResourceClient
}

func toV1(kvpv3 *model.KVPair) *model.KVPair {
	cidrStr := kvpv3.Value.(*apiv3.BlockAffinity).Annotations["projectcalico.org/cidr"]
	host := kvpv3.Value.(*apiv3.BlockAffinity).Annotations["projectcalico.org/host"]
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		panic(err)
	}
	state := model.BlockAffinityState(kvpv3.Value.(*apiv3.BlockAffinity).Spec.State)
	return &model.KVPair{
		Key: model.BlockAffinityKey{
			Host: host,
			CIDR: *cidr,
			UID:  &kvpv3.Value.(*apiv3.BlockAffinity).UID,
		},
		Value: &model.BlockAffinity{
			State: state,
		},
		Revision: kvpv3.Revision,
	}
}

func v3Fields(k model.Key) (name, cidr, host string) {
	// Sanitize the CIDR, replacing characters which
	// are not allowed in the Kubernetes API.
	// e.g., 10.0.0.1/26 -> 10-0-0-1-26
	cidr = fmt.Sprintf("%s", k.(model.BlockAffinityKey).CIDR)
	cidrstr := strings.Replace(cidr, ".", "-", -1)
	cidrstr = strings.Replace(cidrstr, ":", "-", -1)
	cidrstr = strings.Replace(cidrstr, "/", "-", -1)

	// Include the hostname as well.
	host = k.(model.BlockAffinityKey).Host
	name = fmt.Sprintf("%s-%s", host, cidrstr)

	if len(name) >= 253 {
		// If the name is too long, we need to shorten it.
		// Remove enough characters to get it below the 253 character limit,
		// as well as 11 characters to add a hash which helps with uniqueness,
		// and two characters for the `-` separators between clauses.
		name = fmt.Sprintf("%s-%s", host[:252-len(cidrstr)-13], cidrstr)

		// Add a hash to help with uniqueness.
		// Kubernetes requires all names to end with an alphabetic character, so
		// append a 'c' to the end to ensure we always meet this requirement.
		h := sha1.New()
		h.Write([]byte(fmt.Sprintf("%s+%s", host, cidrstr)))
		name = fmt.Sprintf("%s-%sc", name, hex.EncodeToString(h.Sum(nil))[:10])
	}
	return
}

func toV3(kvpv1 *model.KVPair) *model.KVPair {
	name, cidr, host := v3Fields(kvpv1.Key)
	state := kvpv1.Value.(*model.BlockAffinity).State
	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: apiv3.KindBlockAffinity,
		},
		Value: &apiv3.BlockAffinity{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindBlockAffinity,
				APIVersion: "crd.projectcalico.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: kvpv1.Revision,
				Annotations: map[string]string{
					"projectcalico.org/host": host,
					"projectcalico.org/cidr": cidr,
				},
			},
			Spec: apiv3.BlockAffinitySpec{
				State: string(state),
			},
		},
		Revision: kvpv1.Revision,
	}
}

func (c *affinityBlockClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := toV3(kvp)
	//nkvp.Value.(Resource).GetObjectMeta().SetFinalizers([]string{"ipam.projectcalico.org"})
	kvp, err := c.rc.Create(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	return toV1(kvp), nil
}

func (c *affinityBlockClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := toV3(kvp)
	//nkvp.Value.(Resource).GetObjectMeta().SetFinalizers([]string{"ipam.projectcalico.org"})
	kvp, err := c.rc.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	return toV1(kvp), nil
}

func (c *affinityBlockClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	name, _, _ := v3Fields(key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindBlockAffinity,
	}
	kvp, err := c.rc.Delete(ctx, k, revision, key.(model.BlockAffinityKey).UID)
	if err != nil {
		return nil, err
	}
	return toV1(kvp), nil
}

func (c *affinityBlockClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	name, _, _ := v3Fields(key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindBlockAffinity,
	}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}
	return toV1(kvp), nil
}

func (c *affinityBlockClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	l := model.ResourceListOptions{Kind: apiv3.KindBlockAffinity}
	v3list, err := c.rc.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}

	host := list.(model.BlockAffinityListOptions).Host
	requestedIPVersion := list.(model.BlockAffinityListOptions).IPVersion

	kvpl := &model.KVPairList{KVPairs: []*model.KVPair{}}
	for _, i := range v3list.KVPairs {
		v1kvp := toV1(i)
		if host == "" || v1kvp.Key.(model.BlockAffinityKey).Host == host {
			cidr := v1kvp.Key.(model.BlockAffinityKey).CIDR
			cidr2 := &cidr
			if requestedIPVersion == 0 || requestedIPVersion == cidr2.Version() {
				// Matches the given host and IP version.
				kvpl.KVPairs = append(kvpl.KVPairs, v1kvp)
			}
		}
	}
	return kvpl, nil
}

func (c *affinityBlockClient) Watch(ctx context.Context, list model.ListInterface, revision string) (api.WatchInterface, error) {
	log.Warn("Operation Watch is not supported on AffinityBlock type")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: list,
		Operation:  "Watch",
	}
}

func (c *affinityBlockClient) EnsureInitialized() error {
	return nil
}
