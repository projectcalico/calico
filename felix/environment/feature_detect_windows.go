// Copyright (c) 2018-2022 Tigera, Inc. All rights reserved.
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

package environment

type FeatureDetector struct {
}

type Option func(detector *FeatureDetector)

func NewFeatureDetector(overrides map[string]string, opts ...Option) *FeatureDetector {
	fd := &FeatureDetector{}
	for _, opt := range opts {
		opt(fd)
	}
	return fd
}

func (d *FeatureDetector) GetFeatures() *Features {
	return &Features{}
}

// FindBestBinary tries to find an iptables binary for the specific variant (legacy/nftables mode) and returns the name
// of the binary.  Falls back on iptables-restore/iptables-save if the specific variant isn't available.
// Panics if no binary can be found.
func FindBestBinary(lookPath func(file string) (string, error), ipVersion uint8, backendMode, saveOrRestore string) string {
	return "iptables"
}
