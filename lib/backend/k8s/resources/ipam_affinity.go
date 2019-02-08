// Copyright (c) 2019 Tigera, Inc. All rights reserved.

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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"

	apiv3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/projectcalico/libcalico-go/lib/net"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	BlockAffinityResourceName = "BlockAffinities"
	BlockAffinityCRDName      = "blockaffinities.crd.projectcalico.org"
)

func NewBlockAffinityClient(c *kubernetes.Clientset, r *rest.RESTClient) K8sResourceClient {
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

// affinityBlockClient implements the api.Client interface for BlockAffinity objects. It
// handles the translation between v1 objects understood by the IPAM codebase in lib/ipam,
// and the CRDs which are used to actually store the data in the Kubernetes API.
// It uses a customK8sResourceClient under the covers to perform CRUD operations on
// kubernetes CRDs.
type affinityBlockClient struct {
	rc customK8sResourceClient
}

// toV1 converts the given v3 CRD KVPair into a v1 model representation
// which can be passed to the IPAM code.
func (c affinityBlockClient) toV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
	// Parse the CIDR into a struct.
	_, cidr, err := net.ParseCIDR(kvpv3.Value.(*apiv3.BlockAffinity).Spec.CIDR)
	if err != nil {
		log.WithField("cidr", cidr).WithError(err).Error("failed to parse cidr")
		return nil, err
	}
	state := model.BlockAffinityState(kvpv3.Value.(*apiv3.BlockAffinity).Spec.State)
	return &model.KVPair{
		Key: model.BlockAffinityKey{
			CIDR: *cidr,
			Host: kvpv3.Value.(*apiv3.BlockAffinity).Spec.Node,
		},
		Value: &model.BlockAffinity{
			State: state,
		},
		Revision: kvpv3.Revision,
		UID:      &kvpv3.Value.(*apiv3.BlockAffinity).UID,
	}, nil
}

// parseKey parses the given model.Key, returning a suitable name, CIDR
// and host for use in the Kubernetes API.
func (c affinityBlockClient) parseKey(k model.Key) (name, cidr, host string) {
	host = k.(model.BlockAffinityKey).Host
	cidr = fmt.Sprintf("%s", k.(model.BlockAffinityKey).CIDR)
	cidrname := names.CIDRToName(k.(model.BlockAffinityKey).CIDR)

	// Include the hostname as well.
	host = k.(model.BlockAffinityKey).Host
	name = fmt.Sprintf("%s-%s", host, cidrname)

	if len(name) >= 253 {
		// If the name is too long, we need to shorten it.
		// Remove enough characters to get it below the 253 character limit,
		// as well as 11 characters to add a hash which helps with uniqueness,
		// and two characters for the `-` separators between clauses.
		name = fmt.Sprintf("%s-%s", host[:252-len(cidrname)-13], cidrname)

		// Add a hash to help with uniqueness.
		// Kubernetes requires all names to end with an alphabetic character, so
		// append a 'c' to the end to ensure we always meet this requirement.
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s+%s", host, cidrname)))
		name = fmt.Sprintf("%s-%sc", name, hex.EncodeToString(h.Sum(nil))[:10])
	}
	return
}

// toV3 takes the given v1 KVPair and converts it into a v3 representation, suitable
// for writing as a CRD to the Kubernetes API.
func (c affinityBlockClient) toV3(kvpv1 *model.KVPair) *model.KVPair {
	name, cidr, host := c.parseKey(kvpv1.Key)
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
			},
			Spec: apiv3.BlockAffinitySpec{
				State: string(state),
				Node:  host,
				CIDR:  cidr,
			},
		},
		Revision: kvpv1.Revision,
	}
}

func (c *affinityBlockClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	kvp, err := c.rc.Create(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *affinityBlockClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp := c.toV3(kvp)
	kvp, err := c.rc.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *affinityBlockClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	name, _, _ := c.parseKey(kvp.Key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindBlockAffinity,
	}
	kvp, err := c.rc.Delete(ctx, k, kvp.Revision, kvp.UID)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *affinityBlockClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	log.Warn("Operation Delete is not supported on BlockAffinity type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *affinityBlockClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	name, _, _ := c.parseKey(key)
	k := model.ResourceKey{
		Name: name,
		Kind: apiv3.KindBlockAffinity,
	}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}
	v1kvp, err := c.toV1(kvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
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
		v1kvp, err := c.toV1(i)
		if err != nil {
			return nil, err
		}
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
	resl := model.ResourceListOptions{Kind: apiv3.KindBlockAffinity}
	k8sWatchClient := cache.NewListWatchFromClient(c.rc.restClient, c.rc.resource, "", fields.Everything())
	k8sWatch, err := k8sWatchClient.WatchFunc(metav1.ListOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	toKVPair := func(r Resource) (*model.KVPair, error) {
		conv, err := c.rc.convertResourceToKVPair(r)
		if err != nil {
			return nil, err
		}
		return c.toV1(conv)
	}

	return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", toKVPair, k8sWatch), nil
}

func (c *affinityBlockClient) EnsureInitialized() error {
	return nil
}
