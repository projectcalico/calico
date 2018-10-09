// Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

package iptables

import (
	"fmt"
	"reflect"
	"regexp"

	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

type Features struct {
	SNATFullyRandom bool
	MASQFullyRandom bool
}

func MergeFeatures(a, b *Features) *Features {
	var merged Features
	featuresT := reflect.TypeOf(merged)
	for i := 0; i < featuresT.NumField(); i++ {
		if reflect.ValueOf(*a).Field(i).Bool() && reflect.ValueOf(*b).Field(i).Bool() {
			reflect.ValueOf(&merged).Elem().Field(i).SetBool(true)
		}
	}
	return &merged
}

var (
	v1Dot6Dot0  = mustParseVersion("1.6.0")
	v1Dot6Dot2  = mustParseVersion("1.6.2")
	v3Dot14Dot0 = mustParseVersion("3.14.0")
)

func mustParseVersion(v string) *version.Version {
	ver, err := version.NewVersion(v)
	if err != nil {
		logrus.WithError(err).Panic("Failed to parse version.")
	}
	return ver
}

// VersionToFeatures convers an iptables version line as returned by iptables --version into a set of feature flags.
func VersionToFeatures(s string) (*Features, error) {
	re := regexp.MustCompile(`v(\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return nil, fmt.Errorf("iptables returned bad version: %s", s)
	}
	iptablesVersion, err := version.NewVersion(matches[1])
	if err != nil {
		return nil, err
	}
	var features Features
	if iptablesVersion.Compare(v1Dot6Dot0) >= 0 {
		features.SNATFullyRandom = true
	}
	if iptablesVersion.Compare(v1Dot6Dot2) >= 0 {
		features.MASQFullyRandom = true
	}
	return &features, nil
}

func KernelVersionToFeatures(s string) (*Features, error) {
	re := regexp.MustCompile(`Linux version (\d+\.\d+\.\d+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) == 0 {
		return nil, fmt.Errorf("kernel returned bad version: %s", s)
	}
	iptablesVersion, err := version.NewVersion(matches[1])
	if err != nil {
		return nil, err
	}
	var features Features
	if iptablesVersion.Compare(v3Dot14Dot0) >= 0 {
		features.SNATFullyRandom = true
		features.MASQFullyRandom = true
	}
	return &features, nil
}
