// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package codec

import (
	"fmt"

	"github.com/go-playground/form"
	"github.com/google/uuid"
)

var (
	urlPathEncoder  *form.Encoder
	urlQueryEncoder *form.Encoder
	headerEncoder   *form.Encoder
)

func init() {
	urlPathEncoder = form.NewEncoder()
	urlQueryEncoder = form.NewEncoder()
	headerEncoder = form.NewEncoder()

	urlPathEncoder.SetTagName(tagURLPath)
	urlQueryEncoder.SetTagName(tagURLQuery)
	headerEncoder.SetTagName(tagHeader)

	// ModeExplicit ensures that we don't try to parse structs that don't have the tag.
	urlPathEncoder.SetMode(form.ModeExplicit)
	urlQueryEncoder.SetMode(form.ModeExplicit)
	headerEncoder.SetMode(form.ModeExplicit)

	RegisterCustomEncodeTypeFunc(encodeUUID, uuid.UUID{})
}

func RegisterCustomEncodeTypeFunc(fn form.EncodeCustomTypeFunc, types ...interface{}) {
	urlPathEncoder.RegisterCustomTypeFunc(fn, types...)
	urlQueryEncoder.RegisterCustomTypeFunc(fn, types...)
}

// encodeUUID is a form.Encoder encoding function that converts an uuid into a string.
func encodeUUID(obj interface{}) ([]string, error) {
	uid, ok := obj.(uuid.UUID)
	if !ok {
		return nil, fmt.Errorf("object is not a uuid.UUID")
	}

	return []string{uid.String()}, nil
}
