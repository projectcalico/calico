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

package upgrade

import (
	"fmt"

	"github.com/projectcalico/calico/felix/bpf"
)

func UpgradeBPFMap(oldMap, newMap *bpf.PinnedMap) error {
	oldVersion := oldMap.Version
	newVersion := newMap.Version

	newCache := make(map[string]string)

	err := oldMap.Iter(func(k, v []byte) bpf.IteratorAction {
		tmpK, tmpV := newMap.KVasUpgradable(oldVersion, k, v)
		for i := oldVersion; i < newVersion; i++ {
			tmpK = tmpK.Upgrade()
			tmpV = tmpV.Upgrade()
		}
		newCache[string(tmpK.AsBytes())] = string(tmpV.AsBytes())

		return bpf.IterNone
	})

	if err != nil {
		return fmt.Errorf("iterating old map failed: %w", err)
	}

	for k, v := range newCache {
		if err := newMap.Update([]byte(k), []byte(v)); err != nil {
			return fmt.Errorf("new map update failed: %w", err)
		}
	}

	return nil
}
