package server

import (
	"tigera.io/dikastes/proto"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)
type (
	server struct{}
)

func NewServer() (*server) {
	return &server{}
}

func (*server) Check(ctx context.Context, req *authz.Request) (*authz.Response, error) {
	log.Debugf("Check(%v)", req)
	resp := authz.Response{}
	return &resp, nil
}
