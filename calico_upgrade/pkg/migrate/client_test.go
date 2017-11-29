// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package migrate_test

import (
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/libcalico-go/lib/errors"
)

// BackendClientV1 implements the
type BackendClientV1 struct {
	kdd  bool
	kvps map[string]*model.KVPair
}

func (bc BackendClientV1) Apply(kvp *model.KVPair) (*model.KVPair, error) {
	dp, _ := model.KeyToDefaultPath(kvp.Key)
	bc.kvps[dp] = kvp
	return nil, nil
}

func (bc BackendClientV1) Get(k model.Key) (*model.KVPair, error) {
	dp, _ := model.KeyToDefaultPath(k)
	if kvp, ok := bc.kvps[dp]; ok {
		return kvp, nil
	}
	return nil, cerrors.ErrorResourceDoesNotExist{Identifier: k}
}

func (bc BackendClientV1) List(l model.ListInterface) ([]*model.KVPair, error) {
	r := []*model.KVPair{}
	for dp, kvp := range bc.kvps {
		if l.KeyFromDefaultPath(dp) != nil {
			r = append(r, kvp)
		}
	}
	return r, nil
}

func (bc BackendClientV1) IsKDD() bool {
	return bc.kdd
}
