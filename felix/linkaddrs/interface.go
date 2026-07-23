// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linkaddrs

import (
	"github.com/projectcalico/calico/felix/ip"
	"github.com/projectcalico/calico/felix/netlinkshim"
)

// Interface is the interface provided by the standard linkaddrs module.
// Made to support multiple implementations (standard and no-op)
type Interface interface {
	QueueResync()
	SetLinkLocalAddress(_ string, _ ip.CIDR) error
	RemoveLinkLocalAddress(_ string)
	GetNlHandle() (netlinkshim.Interface, error)
	Apply() error
}
