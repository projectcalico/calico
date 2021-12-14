// Copyright (c) 2018 Tigera, Inc. All rights reserved.

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

package checker

import (
	"github.com/projectcalico/calico/app-policy/policystore"

	core_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/genproto/googleapis/rpc/status"
)

type authServer struct {
	stores <-chan *policystore.PolicyStore
	Store  *policystore.PolicyStore
}

// NewServer creates a new authServer and returns a pointer to it.
func NewServer(ctx context.Context, stores <-chan *policystore.PolicyStore) *authServer {
	s := &authServer{stores, nil}
	go s.updateStores(ctx)
	return s
}

// Check applies the currently loaded policy to a network request and renders a policy decision.
func (as *authServer) Check(ctx context.Context, req *authz.CheckRequest) (*authz.CheckResponse, error) {
	log.WithFields(log.Fields{
		"context":         ctx,
		"Req.Method":      req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		"Req.Path":        req.GetAttributes().GetRequest().GetHttp().GetPath(),
		"Req.Protocol":    req.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		"Req.Source":      req.GetAttributes().GetSource(),
		"Req.Destination": req.GetAttributes().GetDestination(),
	}).Debug("Check start")
	resp := authz.CheckResponse{Status: &status.Status{Code: INTERNAL}}
	var st status.Status

	// Ensure that we only access as.Store once per Check call. The authServer can be updated to point to a different
	// store asynchronously with this call, so we use a local variable to reference the PolicyStore for the duration of
	// this call for consistency.
	store := as.Store
	if store == nil {
		log.Warn("Check request before synchronized to Policy, failing.")
		resp.Status.Code = UNAVAILABLE
		return &resp, nil
	}
	store.Read(func(ps *policystore.PolicyStore) { st = checkStore(ps, req) })
	resp.Status = &st
	log.WithFields(log.Fields{
		"Req.Method":               req.GetAttributes().GetRequest().GetHttp().GetMethod(),
		"Req.Path":                 req.GetAttributes().GetRequest().GetHttp().GetPath(),
		"Req.Protocol":             req.GetAttributes().GetRequest().GetHttp().GetProtocol(),
		"Req.Source":               req.GetAttributes().GetSource(),
		"Req.Destination":          req.GetAttributes().GetDestination(),
		"Response.Status":          resp.GetStatus(),
		"Response.HttpResponse":    resp.GetHttpResponse(),
		"Response.DynamicMetadata": resp.GetDynamicMetadata,
	}).Debug("Check complete")
	return &resp, nil
}

func (as *authServer) V2Compat() *authServerV2 {
	return &authServerV2{
		v3: as,
	}
}

type authServerV2 struct {
	v3 *authServer
}

// Check applies the currently loaded policy to a network request and renders a policy decision.
func (as *authServerV2) Check(ctx context.Context, req *authz_v2.CheckRequest) (*authz_v2.CheckResponse, error) {
	resp, err := as.v3.Check(ctx, checkRequestV3Compat(req))
	if err != nil {
		return nil, err
	}
	return checkResponseV2Compat(resp), nil
}

func checkRequestV3Compat(reqV2 *authz_v2.CheckRequest) *authz.CheckRequest {
	return &authz.CheckRequest{
		Attributes: &authz.AttributeContext{
			Source:      peerV3Compat(reqV2.GetAttributes().GetSource()),
			Destination: peerV3Compat(reqV2.GetAttributes().GetDestination()),
			Request: &authz.AttributeContext_Request{
				Time: reqV2.GetAttributes().GetRequest().GetTime(),
				Http: &authz.AttributeContext_HttpRequest{
					Id:       reqV2.GetAttributes().GetRequest().GetHttp().GetId(),
					Method:   reqV2.GetAttributes().GetRequest().GetHttp().GetMethod(),
					Headers:  reqV2.GetAttributes().GetRequest().GetHttp().GetHeaders(),
					Path:     reqV2.GetAttributes().GetRequest().GetHttp().GetPath(),
					Host:     reqV2.GetAttributes().GetRequest().GetHttp().GetHost(),
					Scheme:   reqV2.GetAttributes().GetRequest().GetHttp().GetScheme(),
					Query:    reqV2.GetAttributes().GetRequest().GetHttp().GetQuery(),
					Fragment: reqV2.GetAttributes().GetRequest().GetHttp().GetFragment(),
					Size:     reqV2.GetAttributes().GetRequest().GetHttp().GetSize(),
					Protocol: reqV2.GetAttributes().GetRequest().GetHttp().GetProtocol(),
					Body:     reqV2.GetAttributes().GetRequest().GetHttp().GetBody(),
				},
			},
			ContextExtensions: reqV2.GetAttributes().GetContextExtensions(),
			MetadataContext: &core.Metadata{
				FilterMetadata: reqV2.GetAttributes().GetMetadataContext().GetFilterMetadata(),
			},
		},
	}
}

func peerV3Compat(peerV2 *authz_v2.AttributeContext_Peer) *authz.AttributeContext_Peer {
	peer := authz.AttributeContext_Peer{
		Service:     peerV2.Service,
		Labels:      peerV2.GetLabels(),
		Principal:   peerV2.GetPrincipal(),
		Certificate: peerV2.GetCertificate(),
	}

	switch addr := peerV2.GetAddress().GetAddress().(type) {
	case *core_v2.Address_Pipe:
		peer.Address = &core.Address{
			Address: &core.Address_Pipe{
				Pipe: &core.Pipe{
					Path: addr.Pipe.GetPath(),
					Mode: addr.Pipe.GetMode(),
				},
			},
		}
	case *core_v2.Address_SocketAddress:
		socketAddress := core.SocketAddress{
			Protocol:     core.SocketAddress_Protocol(addr.SocketAddress.GetProtocol()),
			Address:      addr.SocketAddress.GetAddress(),
			ResolverName: addr.SocketAddress.GetResolverName(),
			Ipv4Compat:   addr.SocketAddress.GetIpv4Compat(),
		}
		switch port := addr.SocketAddress.GetPortSpecifier().(type) {
		case *core_v2.SocketAddress_PortValue:
			socketAddress.PortSpecifier = &core.SocketAddress_PortValue{
				PortValue: port.PortValue,
			}
		case *core_v2.SocketAddress_NamedPort:
			socketAddress.PortSpecifier = &core.SocketAddress_NamedPort{
				NamedPort: port.NamedPort,
			}
		}
		peer.Address = &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &socketAddress,
			},
		}
	}

	return &peer
}

func checkResponseV2Compat(respV3 *authz.CheckResponse) *authz_v2.CheckResponse {
	respV2 := authz_v2.CheckResponse{
		Status: respV3.Status,
	}
	switch http3 := respV3.HttpResponse.(type) {
	case *authz.CheckResponse_OkResponse:
		respV2.HttpResponse = &authz_v2.CheckResponse_OkResponse{
			OkResponse: &authz_v2.OkHttpResponse{
				Headers: headersV2Compat(http3.OkResponse.GetHeaders()),
			}}
	case *authz.CheckResponse_DeniedResponse:
		respV2.HttpResponse = &authz_v2.CheckResponse_DeniedResponse{
			DeniedResponse: &authz_v2.DeniedHttpResponse{
				Headers: headersV2Compat(http3.DeniedResponse.GetHeaders()),
				Status:  httpStatusV2Compat(http3.DeniedResponse.GetStatus()),
				Body:    http3.DeniedResponse.GetBody(),
			}}
	}
	return &respV2
}

func headersV2Compat(hdrs []*core.HeaderValueOption) []*core_v2.HeaderValueOption {
	hdrsV2 := make([]*core_v2.HeaderValueOption, len(hdrs))
	for i, hv := range hdrs {
		hdrsV2[i] = &core_v2.HeaderValueOption{
			Header: &core_v2.HeaderValue{
				Key:   hv.GetHeader().GetKey(),
				Value: hv.GetHeader().GetValue(),
			},
		}
	}
	return hdrsV2
}

func httpStatusV2Compat(s *_type.HttpStatus) *type_v2.HttpStatus {
	return &type_v2.HttpStatus{
		Code: type_v2.StatusCode(s.Code),
	}
}

// updateStores pulls PolicyStores off the channel and assigns them.
func (as *authServer) updateStores(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		// Variable assignment is atomic, so this is threadsafe as long as each check call accesses authServer.Store
		// only once.
		case as.Store = <-as.stores:
			log.Info("Switching to new in-sync policy store.")
			continue
		}
	}
}
