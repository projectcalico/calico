// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

	"github.com/projectcalico/calico/release/internal/registry"
	"github.com/projectcalico/calico/release/internal/version"
)

type ErrInvalidImages struct {
	ReleaseName  string
	Stream       string
	Versions     version.Data
	FailedImages []registry.Component
}

func (e ErrInvalidImages) Error() string {
	return fmt.Sprintf("%s hashrelease has %d invalid images: %v", e.ReleaseName, len(e.FailedImages), e.FailedImages)
}

func (e ErrInvalidImages) Unwrap() error {
	return fmt.Errorf("invalid images: %v", e.FailedImages)
}

type ErrHashreleaseAlreadyExists struct {
	ReleaseName string
	Hash        string
	Stream      string
	Versions    version.Data
}

func (e ErrHashreleaseAlreadyExists) Error() string {
	return fmt.Sprintf("hashrelease %s (%s) already exists", e.ReleaseName, e.Hash)
}

func (e ErrHashreleaseAlreadyExists) Unwrap() error {
	return fmt.Errorf("hashrelease %s (%s) already exists", e.ReleaseName, e.Hash)
}
