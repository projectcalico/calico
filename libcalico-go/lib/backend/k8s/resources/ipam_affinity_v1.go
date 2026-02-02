// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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
	"strconv"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/names"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// NewBlockAffinityClientV3 returns a new client for managing BlockAffinity resources, as used by the
// libcalico-go/lib/ipam code.
func NewBlockAffinityClientV1(r rest.Interface, group BackingAPIGroup) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customResourceClient{
		restClient:      r,
		resource:        BlockAffinityResourceName,
		k8sResourceType: reflect.TypeOf(libapiv3.BlockAffinity{}),
		k8sListType:     reflect.TypeOf(libapiv3.BlockAffinityList{}),
		kind:            v3.KindBlockAffinity,
		apiGroup:        group,
	}

	if group == BackingAPIGroupV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they
		// differ.
		rc.k8sResourceType = reflect.TypeOf(v3.BlockAffinity{})
		rc.k8sListType = reflect.TypeOf(v3.BlockAffinityList{})
	}

	return &blockAffinityClientV1{
		rc:      rc,
		crdIsV3: group == BackingAPIGroupV3,
	}
}

type blockAffinityClientV1 struct {
	rc      customResourceClient
	crdIsV3 bool
}

// toModelV1 converts the given v3 CRD KVPair into a v1 model representation
// which can be passed to the IPAM code.
func (c *blockAffinityClientV1) toModelV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
	if c.crdIsV3 {
		// Parse the CIDR into a struct.
		_, cidr, err := net.ParseCIDR(kvpv3.Value.(*v3.BlockAffinity).Spec.CIDR)
		if err != nil {
			log.WithField("cidr", cidr).WithError(err).Error("failed to parse cidr")
			return nil, err
		}
		state := model.BlockAffinityState(kvpv3.Value.(*v3.BlockAffinity).Spec.State)

		// Determine deleted status.
		del := kvpv3.Value.(*v3.BlockAffinity).Spec.Deleted

		// Default affinity type to "host" if not set. Older versions of Calico's CRD backend
		// did not set this field, assuming "host" as the default.
		affinityType := "host"
		if kvpv3.Value.(*v3.BlockAffinity).Spec.Type != "" {
			affinityType = kvpv3.Value.(*v3.BlockAffinity).Spec.Type
		}

		return &model.KVPair{
			Key: model.BlockAffinityKey{
				CIDR:         *cidr,
				AffinityType: affinityType,
				Host:         kvpv3.Value.(*v3.BlockAffinity).Spec.Node,
			},
			Value: &model.BlockAffinity{
				State:   state,
				Deleted: del,
			},
			Revision: kvpv3.Revision,
			UID:      &kvpv3.Value.(*v3.BlockAffinity).UID,
		}, nil

	} else {
		// Parse the CIDR into a struct.
		_, cidr, err := net.ParseCIDR(kvpv3.Value.(*libapiv3.BlockAffinity).Spec.CIDR)
		if err != nil {
			log.WithField("cidr", cidr).WithError(err).Error("failed to parse cidr")
			return nil, err
		}
		state := model.BlockAffinityState(kvpv3.Value.(*libapiv3.BlockAffinity).Spec.State)

		// Determine deleted status.
		deletedString := kvpv3.Value.(*libapiv3.BlockAffinity).Spec.Deleted
		del := false
		if deletedString != "" {
			del, err = strconv.ParseBool(deletedString)
			if err != nil {
				return nil, fmt.Errorf("Failed to parse deleted value as bool: %s", err)
			}
		}

		// Default affinity type to "host" if not set. Older versions of Calico's CRD backend
		// did not set this field, assuming "host" as the default.
		affinityType := "host"
		if kvpv3.Value.(*libapiv3.BlockAffinity).Spec.Type != "" {
			affinityType = kvpv3.Value.(*libapiv3.BlockAffinity).Spec.Type
		}

		return &model.KVPair{
			Key: model.BlockAffinityKey{
				CIDR:         *cidr,
				AffinityType: affinityType,
				Host:         kvpv3.Value.(*libapiv3.BlockAffinity).Spec.Node,
			},
			Value: &model.BlockAffinity{
				State:   state,
				Deleted: del,
			},
			Revision: kvpv3.Revision,
			UID:      &kvpv3.Value.(*libapiv3.BlockAffinity).UID,
		}, nil
	}
}

// parseKey parses the given model.Key, returning a suitable name, CIDR
// and host for use in the Kubernetes API.
func (c *blockAffinityClientV1) parseKey(k model.Key) (name, cidr, host, affinityType string) {
	host = k.(model.BlockAffinityKey).Host
	affinityType = k.(model.BlockAffinityKey).AffinityType
	cidr = fmt.Sprintf("%s", k.(model.BlockAffinityKey).CIDR)
	cidrname := names.CIDRToName(k.(model.BlockAffinityKey).CIDR)

	// Include the hostname as well.
	name = fmt.Sprintf("%s-%s", host, cidrname)

	if len(name) >= 253 {
		// If the name is too long, we need to shorten it.
		// Remove enough characters to get it below the 253 character limit,
		// as well as 11 characters to add a hash which helps with uniqueness,
		// and two characters for the `-` separators between clauses.
		name = fmt.Sprintf("%s-%s", host[:252-len(cidrname)-13], cidrname)

		// Add a hash to help with uniqueness.
		h := sha256.New()
		h.Write([]byte(fmt.Sprintf("%s+%s", host, cidrname)))
		name = fmt.Sprintf("%s-%s", name, hex.EncodeToString(h.Sum(nil))[:11])
	}
	return
}

// toCRD converts the given v1 KVPair containing a model.BlockAffinity into a
// v3 KVPair containing a CRD representation of the BlockAffinity.
func (c *blockAffinityClientV1) toCRD(kvpv1 *model.KVPair) *model.KVPair {
	name, cidr, host, affinityType := c.parseKey(kvpv1.Key)
	state := kvpv1.Value.(*model.BlockAffinity).State

	// Build the CRD representation.
	value := buildCRD(
		string(state),
		host,
		affinityType,
		cidr,
		kvpv1.Value.(*model.BlockAffinity).Deleted,
		name,
		kvpv1.Revision,
		c.crdIsV3,
	)

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: v3.KindBlockAffinity,
		},
		Value:    value,
		Revision: kvpv1.Revision,
	}
}

func (c *blockAffinityClientV1) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.rc.Create(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}

	v1kvp, err := c.toModelV1(nkvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *blockAffinityClientV1) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.rc.Update(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}

	v1kvp, err := c.toModelV1(nkvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *blockAffinityClientV1) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// We need to mark as deleted first, since the Kubernetes API doesn't support
	// compare-and-delete. This update operation allows us to eliminate races with other clients.
	name, _, _, _ := c.parseKey(kvp.Key)
	kvp.Value.(*model.BlockAffinity).Deleted = true
	v1kvp, err := c.Update(ctx, kvp)
	if err != nil {
		return nil, err
	}

	// Now actually delete the object.
	k := model.ResourceKey{Name: name, Kind: libapiv3.KindBlockAffinity}
	kvp, err = c.rc.Delete(ctx, k, v1kvp.Revision, kvp.UID)
	if err != nil {
		return nil, err
	}
	return c.toModelV1(kvp)
}

func (c *blockAffinityClientV1) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	// Delete should not be used for affinities, since we need the object UID for correctness.
	log.Warn("Operation Delete is not supported on BlockAffinity type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *blockAffinityClientV1) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	// Get the object.
	name, _, _, _ := c.parseKey(key)
	k := model.ResourceKey{Name: name, Kind: libapiv3.KindBlockAffinity}
	kvp, err := c.rc.Get(ctx, k, revision)
	if err != nil {
		return nil, err
	}

	// Convert it to v1.
	v1kvp, err := c.toModelV1(kvp)
	if err != nil {
		return nil, err
	}

	// If this object has been marked as deleted, then we need to clean it up and
	// return not found.
	if v1kvp.Value.(*model.BlockAffinity).Deleted {
		if _, err := c.DeleteKVP(ctx, v1kvp); err != nil {
			return nil, err
		}
		return nil, cerrors.ErrorResourceDoesNotExist{Err: fmt.Errorf("Resource was deleted"), Identifier: key}
	}

	return v1kvp, nil
}

func (c *blockAffinityClientV1) List(ctx context.Context, li model.ListInterface, revision string) (*model.KVPairList, error) {
	list := li.(model.BlockAffinityListOptions)
	log.Debugf("Listing v1 block affinities with host %s, affinity type %s, IP version %d", list.Host, list.AffinityType, list.IPVersion)
	l := model.ResourceListOptions{
		Kind:          libapiv3.KindBlockAffinity,
		LabelSelector: model.CalculateBlockAffinityLabelSelector(list),
	}
	crdList, err := c.rc.List(ctx, l, revision)
	if err != nil {
		return nil, err
	}

	host := list.Host
	affinityType := list.AffinityType
	requestedIPVersion := list.IPVersion

	kvpl := &model.KVPairList{
		KVPairs:  []*model.KVPair{},
		Revision: crdList.Revision,
	}
	for _, i := range crdList.KVPairs {
		v1kvp, err := c.toModelV1(i)
		if err != nil {
			return nil, err
		}

		if (host == "" || v1kvp.Key.(model.BlockAffinityKey).Host == host) &&
			(affinityType == "" || v1kvp.Key.(model.BlockAffinityKey).AffinityType == affinityType) {
			cidr := v1kvp.Key.(model.BlockAffinityKey).CIDR
			cidrPtr := &cidr
			if (requestedIPVersion == 0 || requestedIPVersion == cidrPtr.Version()) && !v1kvp.Value.(*model.BlockAffinity).Deleted {
				// Matches the given host and IP version.
				kvpl.KVPairs = append(kvpl.KVPairs, v1kvp)
			}
		}
	}
	return kvpl, nil
}

func (c *blockAffinityClientV1) toKVPairV1(r Resource) (*model.KVPair, error) {
	conv, err := c.rc.convertResourceToKVPair(r)
	if err != nil {
		return nil, err
	}
	return c.toModelV1(conv)
}

func (c *blockAffinityClientV1) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	resl := model.ResourceListOptions{Kind: libapiv3.KindBlockAffinity}
	k8sWatchClient := cache.NewListWatchFromClient(c.rc.restClient, c.rc.resource, "", fields.Everything())
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := k8sWatchClient.WatchFunc(k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", c.toKVPairV1, k8sWatch), nil
}

func (c *blockAffinityClientV1) EnsureInitialized() error {
	return nil
}
