// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package netlinkshim

import (
	"os"
	"strings"

	"github.com/vishvananda/netlink"
)

func IsNotSupported(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "operation not supported")
}

func IsExist(err error) bool {
	if err == nil {
		return false
	}
	return os.IsExist(err) || strings.Contains(err.Error(), "already exists")
}

func IsNotExist(err error) bool {
	if err == nil {
		return false
	}
	if os.IsNotExist(err) {
		return true
	}
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return true
	}
	return strings.Contains(err.Error(), "not found")
}
