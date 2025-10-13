package types

import (
	"net"
	"strconv"

	"k8s.io/apimachinery/pkg/util/sets"
)

type MockEndpoint struct {
	Ip                                 string
	Prt                                uint16
	Local, Ready, Serving, Terminating bool
	ZoneHnts, NodeHnts                 sets.Set[string]
}

func (ep MockEndpoint) String() string              { return net.JoinHostPort(ep.Ip, strconv.Itoa(int(ep.Prt))) }
func (ep MockEndpoint) IP() string                  { return ep.Ip }
func (ep MockEndpoint) IsLocal() bool               { return ep.Local }
func (ep MockEndpoint) Port() int                   { return int(ep.Prt) }
func (ep MockEndpoint) IsReady() bool               { return ep.Ready }
func (ep MockEndpoint) IsServing() bool             { return ep.Serving }
func (ep MockEndpoint) IsTerminating() bool         { return ep.Terminating }
func (ep MockEndpoint) ZoneHints() sets.Set[string] { return ep.ZoneHnts }
func (ep MockEndpoint) NodeHints() sets.Set[string] { return ep.NodeHnts }
