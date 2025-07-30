// Copyright (c) 2025 Tigera, Inc. All rights reserved

package ipsetmember

import (
	"strings"

	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
)

type Protocol uint8

func (p Protocol) MatchesModelProtocol(protocol numorstring.Protocol) bool {
	if protocol.Type == numorstring.NumOrStringNum {
		if protocol.NumVal == 0 {
			// Special case: named ports default to TCP if protocol isn't specified.
			return p == ProtocolTCP
		}
		return protocol.NumVal == uint8(p)
	}
	switch p {
	case ProtocolTCP:
		return strings.ToLower(protocol.StrVal) == "tcp"
	case ProtocolUDP:
		return strings.ToLower(protocol.StrVal) == "udp"
	case ProtocolSCTP:
		return strings.ToLower(protocol.StrVal) == "sctp"
	}
	logrus.WithField("protocol", p).Panic("Unknown protocol")
	return false
}

func (p Protocol) String() string {
	switch p {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolSCTP:
		return "sctp"
	case ProtocolNone:
		return "none"
	default:
		return "unknown"
	}
}

const (
	ProtocolNone Protocol = 0
	ProtocolTCP  Protocol = 6
	ProtocolUDP  Protocol = 17
	ProtocolSCTP Protocol = 132
)
