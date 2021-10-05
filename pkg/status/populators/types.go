// Copyright (c) 2021 Tigera, Inc. All rights reserved.

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

package populator

import (
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	log "github.com/sirupsen/logrus"
)

// Interface for a component to populate its status to node status resource.
type Interface interface {
	Populate(status *apiv3.CalicoNodeStatus) error
	Show()
}

type IPFamily string

const (
	IPFamilyV4 IPFamily = "4"
	IPFamilyV6 IPFamily = "6"
)

func (c IPFamily) String() string {
	return string(c)
}

func (c IPFamily) BirdSuffix() string {
	if c == IPFamilyV4 {
		return ""
	} else if c == IPFamilyV6 {
		return "6"
	} else {
		log.Fatal("Unknown IPFamily")
	}
	return ""
}

func (c IPFamily) Separator() string {
	if c == IPFamilyV4 {
		return "."
	} else if c == IPFamilyV6 {
		return ":"
	} else {
		log.Fatal("Unknown IPFamily")
	}
	return "."
}
