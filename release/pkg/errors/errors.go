// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

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

package errors

import (
	"fmt"

	"github.com/projectcalico/calico/release/internal/hashreleaseserver"
	"github.com/projectcalico/calico/release/internal/registry"
)

type ErrHashreleaseMissingImages struct {
	Hashrelease   hashreleaseserver.Hashrelease
	MissingImages []registry.Component
}

func (e ErrHashreleaseMissingImages) Error() string {
	return fmt.Sprintf("%s hashrelease is missing %d images: %v", e.Hashrelease.Name, len(e.MissingImages), e.MissingImages)
}

func (e ErrHashreleaseMissingImages) Unwrap() error {
	return fmt.Errorf("missing %d images: %v", len(e.MissingImages), e.MissingImages)
}

type ErrHashreleaseExists struct {
	ReleaseName     string
	ReleaseType     string
	Stream          string
	ProductVersion  string
	OperatorVersion string
	Hash            string
}

func (e ErrHashreleaseExists) Error() string {
	return fmt.Sprintf("cannot create %s as %s hashrelease already exists for %s", e.ReleaseName, e.Stream, e.Hash)
}

func (e ErrHashreleaseExists) Unwrap() error {
	return fmt.Errorf("hashrelease already exists for %s", e.Hash)
}
