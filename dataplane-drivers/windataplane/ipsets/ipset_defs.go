//+build windows

package ipsets

import (
	"github.com/projectcalico/felix/dataplane-drivers/windataplane/set"
)

// IPSetMetadata contains the metadata for a particular IP set, such as its name and type.
type IPSetMetadata struct {
	SetID   string
	Type    IPSetType
}

// IPSetsDataplane is interface for managing a plane of ipSet objects.
type IPSetsDataplane interface {
	AddOrReplaceIPSet(setMetadata IPSetMetadata, members []string)
	AddMembers(setID string, newMembers []string)
	RemoveMembers(setID string, removedMembers []string)
	RemoveIPSet(setID string)
}

// IPSetType constants for the different kinds of IP set.
type IPSetType string

const (
	IPSetTypeHashIP  IPSetType = "hash:ip"
	IPSetTypeHashNet IPSetType = "hash:net"
)

func (t IPSetType) SetType() string {
	return string(t)
}

func (t IPSetType) IsValid() bool {
	switch t {
	case IPSetTypeHashIP, IPSetTypeHashNet:
		return true
	}
	return false
}

// IPFamily constants to represent the IP family being managed by this IPSet
type IPFamily string

const (
	IPFamilyV4 = IPFamily("inet")
	IPFamilyV6 = IPFamily("inet6")
)

func (f IPFamily) IsValid() bool {
	switch f {
	case IPFamilyV4, IPFamilyV6:
		return true
	}
	return false
}

// ipSet holds the state for a particular IP set.
type ipSet struct {
	IPSetMetadata
	Members set.Set
}

// IPVersionConfig wraps up the metadata for a particular IP version.
type IPVersionConfig struct {
	Family IPFamily
}

func NewIPVersionConfig(family IPFamily) *IPVersionConfig {
	return &IPVersionConfig{
		Family: family,
	}
}
