package binder

import (
	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	fvcreds "github.com/colabsaumoh/proto-udsuspver/flexvol/creds"
)

const (
	authType = "udsuspver"
)

type Credentials struct {
	WorkloadCredentials fvcreds.Credentials
}

func (c Credentials) AuthType() string {
	return authType
}

func CallerFromContext(ctx context.Context) (fvcreds.Credentials, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return fvcreds.Credentials{}, false
	}
	return CallerFromAuthInfo(peer.AuthInfo)
}

func CallerFromAuthInfo(ainfo credentials.AuthInfo) (fvcreds.Credentials, bool) {
	if ci, ok := ainfo.(Credentials); ok {
		return ci.WorkloadCredentials, true
	}
	return fvcreds.Credentials{}, false
}
