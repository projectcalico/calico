// Copyright (c) 2022 Tigera, Inc. All rights reserved.
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

package mock

import (
	"fmt"

	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/cachingmap"
	v2 "github.com/projectcalico/calico/felix/bpf/mock/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/mock/v3"
	v4 "github.com/projectcalico/calico/felix/bpf/mock/v4"
	v5 "github.com/projectcalico/calico/felix/bpf/mock/v5"
)

func MapV2(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v2.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = Upgrade
	return b
}

func MapV3(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v3.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = Upgrade
	return b
}

func MapV4(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v4.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = Upgrade
	return b
}

func MapV5(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v5.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = Upgrade
	return b
}

func NewKeyV2(k uint32) v2.Key {
	return v2.NewKey(k)
}

func NewKeyV3(k uint32) v3.Key {
	return v3.NewKey(k)
}

func NewKeyV4(k uint32) v4.Key {
	return v4.NewKey(k)
}

func NewKeyV5(k uint32) v5.Key {
	return v5.NewKey(k)
}

func NewValueV2(k uint32) v2.Value {
	return v2.NewValue(k)
}

func NewValueV3(k uint32) v3.Value {
	return v3.NewValue(k)
}

func NewValueV4(k uint32) v4.Value {
	return v4.NewValue(k)
}
func NewValueV5(k uint32) v5.Value {
	return v5.NewValue(k)
}

func getCachingMap(mapParams bpf.MapParameters, mc *bpf.MapContext) (*cachingmap.CachingMap, error) {
	bpfMap := mc.NewPinnedMap(mapParams)
	err := bpfMap.EnsureExists()
	if err != nil {
		return nil, fmt.Errorf("error ensuring map version=%d err=%w", mapParams.Version, err)
	}
	return cachingmap.New(mapParams, bpfMap), nil
}

func getCachingMapFromVersion(version int, mc *bpf.MapContext) (*cachingmap.CachingMap, error) {
	switch version {
	case 2:
		return getCachingMap(v2.MockMapParams, mc)
	case 3:
		return getCachingMap(v3.MockMapParams, mc)
	case 4:
		return getCachingMap(v4.MockMapParams, mc)
	case 5:
		return getCachingMap(v5.MockMapParams, mc)
	default:
		return getCachingMap(v5.MockMapParams, mc)
	}
}

func getKeyValueTypeFromVersion(version int, k, v []byte) (bpf.Upgradable, bpf.Upgradable) {
	switch version {
	case 2:
		var key v2.Key
		var val v2.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	case 3:
		var key v3.Key
		var val v3.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	case 4:
		var key v4.Key
		var val v4.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	case 5:
		var key v5.Key
		var val v5.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	default:
		var key v5.Key
		var val v5.Value
		copy(key[:], k)
		copy(val[:], v)
		return key, val
	}
}

func getBytesFromUpgradable(k, v bpf.Upgradable) ([]byte, []byte) {
	switch k := k.(type) {
	case v2.Key:
		return k.AsBytes(), v.(v2.Value).AsBytes()
	case v3.Key:
		return k.AsBytes(), v.(v3.Value).AsBytes()
	case v4.Key:
		return k.AsBytes(), v.(v4.Value).AsBytes()
	case v5.Key:
		return k.AsBytes(), v.(v5.Value).AsBytes()
	default:
		return k.(v5.Key).AsBytes(), v.(v5.Value).AsBytes()
	}
}

func Upgrade(oldVersion, newVersion int, mc *bpf.MapContext) error {
	oldcachingMap, err := getCachingMapFromVersion(oldVersion, mc)
	if err != nil {
		return err
	}
	newcachingMap, err := getCachingMapFromVersion(newVersion, mc)
	if err != nil {
		return err
	}
	err = oldcachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	err = newcachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	oldcachingMap.IterDataplaneCache(func(k, v []byte) {
		tmpK, tmpV := getKeyValueTypeFromVersion(oldVersion, k, v)
		for i := oldVersion; i < newVersion; i++ {
			tmpK = tmpK.Upgrade()
			tmpV = tmpV.Upgrade()
		}
		newcachingMap.SetDesired(getBytesFromUpgradable(tmpK, tmpV))

	})
	return newcachingMap.ApplyAllChanges()
}
