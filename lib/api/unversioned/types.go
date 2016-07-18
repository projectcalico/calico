// Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

package unversioned

// All resources (and resource lists) implement the Resource interface.
type Resource interface {
	GetTypeMetadata() TypeMetadata
}

// ---- Type metadata ----
//
type TypeMetadata struct {
	Kind       string `json:"kind" validate:"required"`
	APIVersion string `json:"apiVersion" validate:"required"`
}

func (md TypeMetadata) GetTypeMetadata() TypeMetadata {
	return md
}

// ---- Metadata common to all resources ----
type ObjectMetadata struct {
}

// ---- Metadata common to all lists ----
type ListMetadata struct {
}
