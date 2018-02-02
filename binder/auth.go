package binder

import (
	"golang.org/x/net/context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const (
	authType = "udsuspver"
)

// TODO relocate to shared location
type Credentials struct {
	Uid            string
	Workload       string
	Namespace      string
	ServiceAccount string
}

func (c Credentials) AuthType() string {
	return authType
}

func CallerFromContext(ctx context.Context) (Credentials, bool) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return Credentials{}, false
	}
	return CallerFromAuthInfo(peer.AuthInfo)
}

func CallerFromAuthInfo(ainfo credentials.AuthInfo) (Credentials, bool) {
	if ci, ok := ainfo.(Credentials); ok {
		return ci, true
	}
	return Credentials{}, false
}
