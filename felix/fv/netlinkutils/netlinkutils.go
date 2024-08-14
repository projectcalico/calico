// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package netlinkutils

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/calico/felix/netlinkshim"
)

func LinkListRetryEINTR() ([]netlink.Link, error) {
	nlHandle, err := netlinkshim.NewRealNetlink()
	if err != nil {
		log.WithError(err).Error("failed to created netlink handle. Unable to list interfaces")
		return []netlink.Link{}, err
	}

	links, err := nlHandle.LinkList()
	if err != nil {
		log.WithError(err).Error("Failed to list interfaces")
	}
	return links, err
}
