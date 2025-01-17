// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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
