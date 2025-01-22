// Copyright (c) 2020-2025 Tigera, Inc. All rights reserved.
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

package k8sutils

import v1 "k8s.io/api/core/v1"

func GetProtocolAsInt(p v1.Protocol) int {
	switch p {
	case v1.ProtocolUDP:
		return 17
	case v1.ProtocolTCP:
		return 6
	case v1.ProtocolSCTP:
		return 132
	}
	return 0
}

func GetProtocolFromInt(p int) v1.Protocol {
	switch p {
	case 17:
		return v1.ProtocolUDP
	case 6:
		return v1.ProtocolTCP
	case 132:
		return v1.ProtocolSCTP
	}
	return ""
}
