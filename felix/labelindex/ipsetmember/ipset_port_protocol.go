// Copyright (c) 2025-2026 Tigera, Inc. All rights reserved

package ipsetmember

import (
	"strings"

	"github.com/projectcalico/api/pkg/lib/numorstring"
	"github.com/sirupsen/logrus"
)

type Protocol uint8

func ProtocolFrom(p numorstring.Protocol) Protocol {
	switch {
	case ProtocolUDP.MatchesModelProtocol(p):
		return ProtocolUDP
	case ProtocolSCTP.MatchesModelProtocol(p):
		return ProtocolSCTP
	default:
		return ProtocolTCP
	}
}

func (p Protocol) MatchesModelProtocol(protocol numorstring.Protocol) bool {
	if protocol.Type == numorstring.NumOrStringNum {
		if protocol.NumVal == 0 {
			// Special case: named ports default to Any if protocol isn't specified.
			return p == ProtocolAny
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
	case ProtocolAny:
		return true
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
	case ProtocolAny:
		return "any"
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
	ProtocolAny  Protocol = 255
)
