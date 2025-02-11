// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

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
	"context"
	"fmt"
	"os"

	core_v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authz_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	authz_v2alpha "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	type_v2 "github.com/envoyproxy/go-control-plane/envoy/type"
	_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"github.com/projectcalico/calico/app-policy/policystore"
)

type authServer struct {
	Store            policystore.PolicyStoreManager
	checkProviders   []CheckProvider
	subscriptionType string
}

type AuthServerOption func(*authServer)

// NewServer creates a new authServer and returns a pointer to it.
func NewServer(
	ctx context.Context,
	storeManager policystore.PolicyStoreManager,
	opts ...AuthServerOption,
) *authServer {
	s := &authServer{Store: storeManager}
	for _, o := range opts {
		o(s)
	}
	return s
}

func WithSubscriptionType(s string) AuthServerOption {
	return func(as *authServer) {
		as.subscriptionType = s
	}
}

func WithRegisteredCheckProvider(c CheckProvider) AuthServerOption {
	log.Info("registering check provider: ", c.Name())
	return func(as *authServer) {
		// don't re-register providers that are already registered
		for _, p := range as.checkProviders {
			if c.Name() == p.Name() {
				log.Warn("encountered attempt to register already-registered check provider")
				return
			}
		}
		as.checkProviders = append(as.checkProviders, c)
	}
}

func (as *authServer) RegisterGRPCServices(gs *grpc.Server) {
	authz.RegisterAuthorizationServer(gs, as)

	authz_v2.RegisterAuthorizationServer(gs, as.V2Compat())
	authz_v2alpha.RegisterAuthorizationServer(gs, as.V2Compat())
}

// Check applies the currently loaded policy to a network request and renders a policy decision.
func (as *authServer) Check(ctx context.Context, req *authz.CheckRequest) (*authz.CheckResponse, error) {
	hostname, _ := os.Hostname()
	logCtx := log.WithContext(ctx).WithField("hostname", hostname)
	if logCtx.Logger.IsLevelEnabled(log.DebugLevel) {
		logCtx.Debug("Check start: ", req.Attributes.String())
	}

	resp := &authz.CheckResponse{Status: &status.Status{Code: INTERNAL}}
	var err error
	// Ensure that we only access as.Store once per Check call. The authServer can be updated to point to a different
	// store asynchronously with this call, so we use a local variable to reference the PolicyStore for the duration of
	// this call for consistency.
	store := as.Store
	logCtx.Debugf("attempting store read at %p", store)
	store.DoWithReadLock(func(ps *policystore.PolicyStore) {
		if ps == nil {
			panic("bug: policyStore is nil and shouldn't happen.. ever")
		}

		var unknownChecks int
	T:
		for _, checkProvider := range as.checkProviders {
			checkName := checkProvider.Name()
			logCtx.Debugf("checking request with provider %s", checkName)

			// Check if provider is enabled in case is TPROXY or
			// sidecar
			if !checkProvider.EnabledForRequest(ps, req) {
				continue
			}

			resp, err = checkProvider.Check(ps, req)
			if err != nil {
				msg := fmt.Sprintf("check provider %s failed with error %v", checkName, err)
				logCtx.Error(msg)
				resp = &authz.CheckResponse{Status: &status.Status{
					Code:    INTERNAL,
					Message: msg,
				}}
				break T
			}

			switch v := resp.Status.Code; v {
			case OK:
				// current check passes but we may need to go through all the other checks
				logCtx.Debugf("request passes %s check", checkName)
				continue T
			case UNKNOWN:
				// check provider tried to process result, but there's no clear decision; or
				// check provider is requesting to continue to next check
				logCtx.Debugf("request returned unknown for %s check", checkName)
				unknownChecks++
				continue T
			default:
				logCtx.Errorf("request denied by %s with status %s", checkName, code.Code(v).String())
				break T
			}
		}
		logCtx.Debugf(
			"All checks complete. final response is: %s",
			code.Code(resp.Status.Code),
		)

		// all checks returned unknown
		if unknownChecks == len(as.checkProviders) {
			resp.Status.Code = UNKNOWN
		}
	})

	if logCtx.Logger.IsLevelEnabled(log.DebugLevel) {
		logCtx.WithFields(log.Fields{
			"code": code.Code(resp.Status.Code),
			"msg":  resp.Status.Message,
		}).Debug("Check complete: ", req.String())
	}

	return resp, nil
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
