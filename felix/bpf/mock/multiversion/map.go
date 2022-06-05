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

package multiversion

import (
	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/bpfmap"
	v2 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v2"
	v3 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v3"
	v4 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v4"
	v5 "github.com/projectcalico/calico/felix/bpf/mock/multiversion/v5"
)

func GetMapParams(version int) bpf.MapParameters {
	switch version {
	case 2:
		return v2.MockMapParams
	case 3:
		return v3.MockMapParams
	case 4:
		return v4.MockMapParams
	case 5:
		return v5.MockMapParams
	default:
		return v5.MockMapParams
	}
}

func GetKeyValueTypeFromVersion(version int, k, v []byte) (bpf.Upgradable, bpf.Upgradable) {
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

func MapV2(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v2.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
	b.(*bpf.PinnedMap).GetMapParams = GetMapParams
	b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}

func MapV3(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v3.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
	b.(*bpf.PinnedMap).GetMapParams = GetMapParams
	b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}

func MapV4(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v4.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
	b.(*bpf.PinnedMap).GetMapParams = GetMapParams
	b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}

func MapV5(mc *bpf.MapContext) bpf.Map {
	b := mc.NewPinnedMap(v5.MockMapParams)
	b.(*bpf.PinnedMap).UpgradeFn = bpfmap.Upgrade
	b.(*bpf.PinnedMap).GetMapParams = GetMapParams
	b.(*bpf.PinnedMap).KVasUpgradable = GetKeyValueTypeFromVersion
	return b
}
