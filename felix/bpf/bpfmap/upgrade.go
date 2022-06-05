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

package bpfmap

import (
	"github.com/projectcalico/calico/felix/bpf"
	"github.com/projectcalico/calico/felix/bpf/cachingmap"
)

func Upgrade(oldMap, newMap *bpf.PinnedMap) error {
	oldVersion := oldMap.Version
	newVersion := newMap.Version
	oldCachingMap := cachingmap.New(oldMap.MapParameters, oldMap)
	newCachingMap := cachingmap.New(newMap.MapParameters, newMap)
	err := oldCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	err = newCachingMap.LoadCacheFromDataplane()
	if err != nil {
		return err
	}
	oldCachingMap.IterDataplaneCache(func(k, v []byte) {
		tmpK, tmpV := oldMap.KVasUpgradable(oldVersion, k, v)
		for i := oldVersion; i < newVersion; i++ {
			tmpK = tmpK.Upgrade()
			tmpV = tmpV.Upgrade()
		}
		newCachingMap.SetDesired(tmpK.AsBytes(), tmpV.AsBytes())

	})
	return newCachingMap.ApplyAllChanges()

}
