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
	"strconv"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const (
	BlockAffinityResourceName = "BlockAffinities"
)

func NewBlockAffinityClient(r rest.Interface, useV3 bool) K8sResourceClient {
	// Create a resource client which manages k8s CRDs.
	rc := customResourceClient{
		restClient:      r,
		resource:        BlockAffinityResourceName,
		k8sResourceType: reflect.TypeOf(libapiv3.BlockAffinity{}),
		k8sListType:     reflect.TypeOf(libapiv3.BlockAffinityList{}),
		kind:            v3.KindBlockAffinity,
		noTransform:     useV3,
	}

	if useV3 {
		// If this is a v3 resource, then we need to use the v3 API types, as they
		// differ.
		rc.k8sResourceType = reflect.TypeOf(v3.BlockAffinity{})
		rc.k8sListType = reflect.TypeOf(v3.BlockAffinityList{})
	}

	// TODO: CASEY
	return &blockAffinityClient{
		rc:      rc,
		crdIsV3: useV3,
	}
}

// blockAffinityClient implements the api.Client interface for BlockAffinity objects. It
// handles the translation between v1 objects understood by the IPAM codebase in lib/ipam,
// and the CRDs which are used to actually store the data in the Kubernetes API.
// It uses a customK8sResourceClient under the covers to perform CRUD operations on
// kubernetes CRDs.
type blockAffinityClient struct {
	rc      customResourceClient
	crdIsV3 bool
}

// toModelV1 converts the given v3 CRD KVPair into a v1 model representation
// which can be passed to the IPAM code.
func (c *blockAffinityClient) toModelV1(kvpv3 *model.KVPair) (*model.KVPair, error) {
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
func (c *blockAffinityClient) parseKey(k model.Key) (name, cidr, host, affinityType string) {
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
func (c *blockAffinityClient) toCRD(kvpv1 *model.KVPair) *model.KVPair {
	name, cidr, host, affinityType := c.parseKey(kvpv1.Key)
	state := kvpv1.Value.(*model.BlockAffinity).State
	var value Resource

	if c.crdIsV3 {
		// If this is a v3 resource, then we need to use the canonical v3 API version and types.
		ba := &v3.BlockAffinity{
			TypeMeta: metav1.TypeMeta{
				Kind:       v3.KindBlockAffinity,
				APIVersion: "projectcalico.org/v3",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: kvpv1.Revision,
			},
			Spec: v3.BlockAffinitySpec{
				State:   v3.BlockAffinityState(state),
				Node:    host,
				Type:    affinityType,
				CIDR:    cidr,
				Deleted: kvpv1.Value.(*model.BlockAffinity).Deleted,
			},
		}
		model.EnsureBlockAffinityLabelsV3(ba)
		value = ba
	} else {
		// If this is a v1 resource, then we need to use the old v1 API version and types.
		ba := &libapiv3.BlockAffinity{
			TypeMeta: metav1.TypeMeta{
				Kind:       libapiv3.KindBlockAffinity,
				APIVersion: "crd.projectcalico.org/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:            name,
				ResourceVersion: kvpv1.Revision,
			},
			Spec: libapiv3.BlockAffinitySpec{
				State:   string(state),
				Node:    host,
				Type:    affinityType,
				CIDR:    cidr,
				Deleted: fmt.Sprintf("%t", kvpv1.Value.(*model.BlockAffinity).Deleted),
			},
		}
		model.EnsureBlockAffinityLabels(ba)
		value = ba
	}

	return &model.KVPair{
		Key: model.ResourceKey{
			Name: name,
			Kind: v3.KindBlockAffinity,
		},
		Value:    value,
		Revision: kvpv1.Revision,
	}
}

// isV1BlockAffinityKey checks if the key is in the v1 format.
func isV1BlockAffinityKey(key model.Key) bool {
	switch key.(type) {
	case model.BlockAffinityKey:
		return true
	case model.ResourceKey:
		return false
	default:
		log.Panic("blockAffinityClient : wrong key interface type")
	}
	return false
}

// createModelV1 creates the given KVPair in the Kubernetes API. It assumes that the input is in v1 format
// and converts it to a CRD before creating it. The returned KVPair is converted back to v1 format.
func (c *blockAffinityClient) createModelV1(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.createCRD(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}

	v1kvp, err := c.toModelV1(nkvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

// createCRD creates the given KVPair in the Kubernetes API. It assumes that the input is already in CRD format.
func (c *blockAffinityClient) createCRD(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Create(ctx, ensureV3Labels(kvp))
}

func ensureV3Labels(kvp *model.KVPair) *model.KVPair {
	switch kvp.Value.(type) {
	case *v3.BlockAffinity:
		val := kvp.Value.(*v3.BlockAffinity)
		val = val.DeepCopy()
		model.EnsureBlockAffinityLabelsV3(val)
		newKVP := *kvp
		newKVP.Value = val
		return &newKVP
	case *libapiv3.BlockAffinity:
		val := kvp.Value.(*libapiv3.BlockAffinity)
		val = val.DeepCopy()
		model.EnsureBlockAffinityLabels(val)
		newKVP := *kvp
		newKVP.Value = val
		return &newKVP
	}
	// Should never happen.
	log.Panicf("BUG: ensureV3Labels called with non-BlockAffinity value of type %T", kvp.Value)
	return nil
}

func (c *blockAffinityClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	if isV1BlockAffinityKey(kvp.Key) {
		// This is a model v1 resource, convert it to a CRD and create it.
		return c.createModelV1(ctx, kvp)
	}
	// If this is a V3 resource, then it is already in CRD format.
	return c.createCRD(ctx, kvp)
}

func (c *blockAffinityClient) updateModelV1(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	nkvp, err := c.updateCRD(ctx, c.toCRD(kvp))
	if err != nil {
		return nil, err
	}

	v1kvp, err := c.toModelV1(nkvp)
	if err != nil {
		return nil, err
	}
	return v1kvp, nil
}

func (c *blockAffinityClient) updateCRD(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return c.rc.Update(ctx, ensureV3Labels(kvp))
}

func (c *blockAffinityClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	if isV1BlockAffinityKey(kvp.Key) {
		// If this is a V1 resource, then it is from the IPAM code. Convert it to a CRD and update it.
		return c.updateModelV1(ctx, kvp)
	}
	// If this is a V3 resource, then it is already in CRD format.
	return c.updateCRD(ctx, kvp)
}

func (c *blockAffinityClient) deleteModelV1(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
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

func (c *blockAffinityClient) deleteCRD(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	// We need to mark as deleted first, since the Kubernetes API doesn't support
	// compare-and-delete. This update operation allows us to eliminate races with other clients.
	var err error
	nkvp := kvp
	if kvp.Value == nil {
		// Need to check if a value is given since V3 deletes can be made by providing a key only.
		// Look up missing values with the provided key.
		nkvp, err = c.getCRD(ctx, kvp.Key.(model.ResourceKey), kvp.Revision)
		if err != nil {
			if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
				return nil, fmt.Errorf("Unable to find block affinity. Block affinity may have already been deleted.")
			}
			return nil, fmt.Errorf("Error retrieving block affinity for deletion: %s", err)
		}
	}

	// Pass in the revision for the key-value pair to ensure that deletion occurs for the specified revision,
	// not the revision that is retrieved by the above Get (which should be the most recent).
	if kvp.Revision == "" {
		return nil, fmt.Errorf("Unable to delete block affinity without a resource version")
	}
	nkvp.Revision = kvp.Revision
	nkvp.Value.(*v3.BlockAffinity).Spec.Deleted = true
	nkvp, err = c.Update(ctx, nkvp)
	if err != nil {
		return nil, err
	}

	// Now actually delete the object.
	return c.rc.Delete(ctx, nkvp.Key, nkvp.Revision, &nkvp.Value.(*v3.BlockAffinity).UID)
}

func (c *blockAffinityClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	if isV1BlockAffinityKey(kvp.Key) {
		// If this is a V1 resource, then it is from the IPAM code.
		// Convert it, but treat it as a V1 resource.
		return c.deleteModelV1(ctx, kvp)
	}
	// If this is a V3 resource, then it is already in CRD format.
	return c.deleteCRD(ctx, kvp)
}

func (c *blockAffinityClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	// Delete should not be used for affinities, since we need the object UID for correctness.
	log.Warn("Operation Delete is not supported on BlockAffinity type - use DeleteKVP")
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
	}
}

func (c *blockAffinityClient) getModelV1(ctx context.Context, key model.BlockAffinityKey, revision string) (*model.KVPair, error) {
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

func (c *blockAffinityClient) getCRD(ctx context.Context, key model.ResourceKey, revision string) (*model.KVPair, error) {
	return c.rc.Get(ctx, key, revision)
}

func (c *blockAffinityClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	if isV1BlockAffinityKey(key) {
		// The client is asking for a v1 formatted resource, so convert it and return it.
		return c.getModelV1(ctx, key.(model.BlockAffinityKey), revision)
	}

	// The client is asking for a v3 formatted resource, so just return it directly.
	return c.getCRD(ctx, key.(model.ResourceKey), revision)
}

func isV1List(list model.ListInterface) bool {
	switch list.(type) {
	case model.BlockAffinityListOptions:
		return true
	case model.ResourceListOptions:
		return false
	default:
		log.Panic("blockAffinityClient : wrong key interface type")
	}
	return false
}

func (c *blockAffinityClient) listModelV1(ctx context.Context, list model.BlockAffinityListOptions, revision string) (*model.KVPairList, error) {
	log.Debugf("Listing v1 block affinities with host %s, affinity type %s, IP version %d", list.Host, list.AffinityType, list.IPVersion)
	l := model.ResourceListOptions{
		Kind:          libapiv3.KindBlockAffinity,
		LabelSelector: model.CalculateBlockAffinityLabelSelector(list),
	}
	crdList, err := c.listCRD(ctx, l, revision)
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

func (c *blockAffinityClient) listCRD(ctx context.Context, list model.ResourceListOptions, revision string) (*model.KVPairList, error) {
	log.Debugf("Listing v3 block affinities matching %v, revision=%v", list, revision)
	return c.rc.List(ctx, list, revision)
}

func (c *blockAffinityClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	if isV1List(list) {
		// If this is a V1 resource, then it is from the IPAM code.
		// Convert it, but treat it as a V1 resource.
		return c.listModelV1(ctx, list.(model.BlockAffinityListOptions), revision)
	}
	// If this is a V3 resource, then it is already in CRD format.
	return c.listCRD(ctx, list.(model.ResourceListOptions), revision)
}

func (c *blockAffinityClient) toKVPairV1(r Resource) (*model.KVPair, error) {
	conv, err := c.rc.convertResourceToKVPair(r)
	if err != nil {
		return nil, err
	}
	return c.toModelV1(conv)
}

func (c *blockAffinityClient) toKVPairV3(r Resource) (*model.KVPair, error) {
	return c.rc.convertResourceToKVPair(r)
}

func (c *blockAffinityClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	resl := model.ResourceListOptions{Kind: libapiv3.KindBlockAffinity}
	k8sWatchClient := cache.NewListWatchFromClient(c.rc.restClient, c.rc.resource, "", fields.Everything())
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := k8sWatchClient.WatchFunc(k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	if isV1List(list) {
		// If this is a V1 resource, then it is from the IPAM code.
		// Convert resources back to a V1 resource.
		return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", c.toKVPairV1, k8sWatch), nil
	}

	return newK8sWatcherConverter(ctx, resl.Kind+" (custom)", c.toKVPairV3, k8sWatch), nil
}

func (c *blockAffinityClient) EnsureInitialized() error {
	return nil
}
