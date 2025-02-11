// Copyright (c) 2024 Tigera, Inc. All rights reserved.
package checker

import (
	"net"
	"strings"

	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	log "github.com/sirupsen/logrus"
)

// CheckRequestToFlowAdapter adapts CheckRequest to the l4 and l7 flow interfaces for use in the
// matchers.
type CheckRequestToFlowAdapter struct {
	flow *authz.CheckRequest
}

func NewCheckRequestToFlowAdapter(req *authz.CheckRequest) *CheckRequestToFlowAdapter {
	return &CheckRequestToFlowAdapter{flow: req}
}

func (a *CheckRequestToFlowAdapter) GetSourceIP() net.IP {
	if a.flow == nil || a.flow.GetAttributes().GetSource().GetAddress().GetSocketAddress() == nil {
		return nil
	}
	return net.ParseIP(a.flow.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetAddress())
}

func (a *CheckRequestToFlowAdapter) GetDestIP() net.IP {
	if a.flow == nil || a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress() == nil {
		return nil
	}
	return net.ParseIP(a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetAddress())
}

func (a *CheckRequestToFlowAdapter) GetSourcePort() int {
	if a.flow == nil || a.flow.GetAttributes().GetSource().GetAddress().GetSocketAddress() == nil {
		return 0
	}
	return int(a.flow.GetAttributes().GetSource().GetAddress().GetSocketAddress().GetPortValue())
}

func (a *CheckRequestToFlowAdapter) GetDestPort() int {
	if a.flow == nil || a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress() == nil {
		return 0
	}
	return int(a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetPortValue())
}

func (a *CheckRequestToFlowAdapter) GetProtocol() int {
	if a.flow == nil || a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress() == nil {
		// Default to TCP if protocol is not set.
		return 6
	}
	protocol := a.flow.GetAttributes().GetDestination().GetAddress().GetSocketAddress().GetProtocol().String()
	if p, ok := protocolMap[strings.ToLower(protocol)]; ok {
		return p
	}
	log.Warnf("unsupported protocol: %s, defaulting to TCP", protocol)
	return 6
}

func (a *CheckRequestToFlowAdapter) GetHttpMethod() *string {
	if a.flow == nil || a.flow.GetAttributes().GetRequest().GetHttp() == nil {
		return nil
	}
	method := a.flow.GetAttributes().GetRequest().GetHttp().GetMethod()
	return &method
}

func (a *CheckRequestToFlowAdapter) GetHttpPath() *string {
	if a.flow == nil || a.flow.GetAttributes().GetRequest().GetHttp() == nil {
		return nil
	}
	path := a.flow.GetAttributes().GetRequest().GetHttp().GetPath()
	return &path
}

func (a *CheckRequestToFlowAdapter) GetSourcePrincipal() *string {
	if a.flow == nil {
		return nil
	}
	principal := a.flow.GetAttributes().GetSource().GetPrincipal()
	return &principal
}

func (a *CheckRequestToFlowAdapter) GetDestPrincipal() *string {
	if a.flow == nil {
		return nil
	}
	principal := a.flow.GetAttributes().GetDestination().GetPrincipal()
	return &principal
}

func (a *CheckRequestToFlowAdapter) GetSourceLabels() map[string]string {
	if a.flow == nil {
		return nil
	}
	return a.flow.GetAttributes().GetSource().GetLabels()
}

func (a *CheckRequestToFlowAdapter) GetDestLabels() map[string]string {
	if a.flow == nil {
		return nil
	}
	return a.flow.GetAttributes().GetDestination().GetLabels()
}
