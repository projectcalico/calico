// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package migrate

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
)

type migrateIPAM struct {
	client          bapi.Client
	BlockAffinities []*BlockAffinityKVPair `json:"block_affinities,omitempty"`
	IPAMBlocks      []*IPAMBlockKVPair     `json:"blocks,omitempty"`
	IPAMHandles     []*IPAMHandleKVPair    `json:"handles,omitempty"`
	IPAMConfig      *IPAMConfigKVPair      `json:"config,omitempty"`
}

type BlockAffinityKVPair struct {
	Key   string
	Value *model.BlockAffinity
	TTL   time.Duration // For writes, if non-zero, key has a TTL.
}

type IPAMBlockKVPair struct {
	Key   string
	Value *model.AllocationBlock
	TTL   time.Duration // For writes, if non-zero, key has a TTL.
}

type IPAMHandleKVPair struct {
	Key   string
	Value *model.IPAMHandle
	TTL   time.Duration // For writes, if non-zero, key has a TTL.
}

type IPAMConfigKVPair struct {
	Key   string
	Value *model.IPAMConfig
	TTL   time.Duration // For writes, if non-zero, key has a TTL.
}

// ipamResults contains the results from executing an IPAM backend command
type ipamResults struct {
	// The number of resources that are being configured.
	numResources int

	// The number of resources that were actually configured.  This will
	// never be 0 without an associated error.
	numHandled int

	// Errors associated with individual resources
	resErrs []error
}

func NewMigrateIPAM(c client.Interface) *migrateIPAM {
	type accessor interface {
		Backend() bapi.Client
	}
	bc := c.(accessor).Backend()
	return &migrateIPAM{
		client: bc,
	}
}

func (m *migrateIPAM) PullFromDatastore() error {
	ctx := context.Background()

	blockKVList, err := m.client.List(ctx, model.BlockListOptions{}, "")
	if err != nil {
		return err
	}

	blockAffinityKVList, err := m.client.List(ctx, model.BlockAffinityListOptions{}, "")
	if err != nil {
		return err
	}

	ipamHandleKVList, err := m.client.List(ctx, model.IPAMHandleListOptions{}, "")
	if err != nil {
		return err
	}

	ipamConfigKV, err := m.client.Get(ctx, model.IPAMConfigKey{}, "")
	if err != nil {
		// If the resource does not exist, do not throw the error
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			return err
		}
	}

	// Convert all of the abstract KV Pairs into the appropriate types.
	blocks := []*IPAMBlockKVPair{}
	for _, item := range blockKVList.KVPairs {
		blockKey, err := model.KeyToDefaultPath(item.Key)
		if err != nil {
			return fmt.Errorf("Error serializing BlockKey: %s", err)
		}

		block, ok := item.Value.(*model.AllocationBlock)
		if !ok {
			return fmt.Errorf("Could not convert %+v to an AllocationBlock", item.Value)
		}
		blocks = append(blocks, &IPAMBlockKVPair{
			Key:   blockKey,
			Value: block,
			TTL:   item.TTL,
		})
	}

	blockAffinities := []*BlockAffinityKVPair{}
	for _, item := range blockAffinityKVList.KVPairs {
		blockAffinityKey, err := model.KeyToDefaultPath(item.Key)
		if err != nil {
			return fmt.Errorf("Error serializing BlockAffinityKey: %s", err)
		}

		blockAffinity, ok := item.Value.(*model.BlockAffinity)
		if !ok {
			return fmt.Errorf("Could not convert %+v to a BlockAffinity", item.Value)
		}
		blockAffinities = append(blockAffinities, &BlockAffinityKVPair{
			Key:   blockAffinityKey,
			Value: blockAffinity,
			TTL:   item.TTL,
		})
	}

	ipamHandles := []*IPAMHandleKVPair{}
	for _, item := range ipamHandleKVList.KVPairs {
		handleKey, err := model.KeyToDefaultPath(item.Key)
		if err != nil {
			return fmt.Errorf("Error serializing IPAMHandleKey: %s", err)
		}
		handle, ok := item.Value.(*model.IPAMHandle)
		if !ok {
			return fmt.Errorf("Could not convert %+v to an IPAMHandle", item.Value)
		}
		ipamHandles = append(ipamHandles, &IPAMHandleKVPair{
			Key:   handleKey,
			Value: handle,
			TTL:   item.TTL,
		})
	}

	var ipamConfig *IPAMConfigKVPair
	if ipamConfigKV != nil {
		configKey, err := model.KeyToDefaultPath(ipamConfigKV.Key)
		if err != nil {
			return fmt.Errorf("Error serializing IPAMConfigKey: %s", err)
		}
		config, ok := ipamConfigKV.Value.(*model.IPAMConfig)
		if !ok {
			return fmt.Errorf("Could not convert %+v to an IPAMConfig", ipamConfigKV.Value)
		}
		ipamConfig = &IPAMConfigKVPair{
			Key:   configKey,
			Value: config,
			TTL:   ipamConfigKV.TTL,
		}
	}

	// Store the information
	m.BlockAffinities = blockAffinities
	m.IPAMBlocks = blocks
	m.IPAMHandles = ipamHandles
	m.IPAMConfig = ipamConfig
	return nil
}

func (m *migrateIPAM) PushToDatastore() ipamResults {
	ctx := context.Background()
	errs := []error{}
	handled := 0

	for _, bakv := range m.BlockAffinities {
		kv := &model.KVPair{
			Key:   model.BlockAffinityListOptions{}.KeyFromDefaultPath(bakv.Key),
			Value: bakv.Value,
			TTL:   bakv.TTL,
		}
		created, err := m.client.Create(ctx, kv)
		if err != nil {
			errs = append(errs, fmt.Errorf("Error trying to create block affinity %s: %s\n", kv.Key.String(), err))
		}
		log.Debugf("Created Block Affinity: %+v", created)
		handled++
	}

	for _, bkv := range m.IPAMBlocks {
		// Need to recreate the BlockKey since the CIDR is not stored in the json representation.
		kv := &model.KVPair{
			Key:   model.BlockListOptions{}.KeyFromDefaultPath(bkv.Key),
			Value: bkv.Value,
			TTL:   bkv.TTL,
		}
		created, err := m.client.Create(ctx, kv)
		if err != nil {
			errs = append(errs, fmt.Errorf("Error trying to create block affinity %s: %s\n", kv.Key.String(), err))
		}
		log.Debugf("Created IPAM Block: %+v", created)
		handled++
	}

	for _, hkv := range m.IPAMHandles {
		// Need to copy over the handle ID since it isn't stored in the json representation.
		key := model.IPAMHandleListOptions{}.KeyFromDefaultPath(hkv.Key)
		handleKey, ok := key.(model.IPAMHandleKey)
		if !ok {
			errs = append(errs, fmt.Errorf("Unable to convert %s to an IPAMHandleKey\n", key))
		}
		hkv.Value.HandleID = handleKey.HandleID

		kv := &model.KVPair{
			Key:   handleKey,
			Value: hkv.Value,
			TTL:   hkv.TTL,
		}
		created, err := m.client.Create(ctx, kv)
		if err != nil {
			errs = append(errs, fmt.Errorf("Error trying to create block affinity %s: %s\n", kv.Key.String(), err))
		}
		log.Debugf("Created IPAM Handle: %+v", created)
		handled++
	}

	ipamConfigCount := 0
	if m.IPAMConfig != nil {
		ipamConfigCount = 1
		kv := &model.KVPair{
			// IPAM Config key is always the same
			Key:   model.IPAMConfigKey{},
			Value: m.IPAMConfig.Value,
			TTL:   m.IPAMConfig.TTL,
		}
		created, err := m.client.Create(ctx, kv)
		if err != nil {
			errs = append(errs, fmt.Errorf("Error trying to create block affinity %s: %s\n", kv.Key.String(), err))
		}
		log.Debugf("Created IPAM Config: %+v", created)
		handled++
	}

	return ipamResults{
		numResources: len(m.BlockAffinities) + len(m.IPAMBlocks) + len(m.IPAMHandles) + ipamConfigCount,
		numHandled:   handled,
		resErrs:      errs,
	}
}

func (m *migrateIPAM) IsEmpty() bool {
	ipamConfigCount := 0
	if m.IPAMConfig != nil {
		ipamConfigCount = 1
	}

	return len(m.BlockAffinities)+len(m.IPAMBlocks)+len(m.IPAMHandles)+ipamConfigCount == 0
}
