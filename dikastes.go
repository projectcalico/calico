package main

import (
	"net"

	"tigera.io/dikastes/proto"
	"tigera.io/dikastes/server"

	docopt "github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server [options]

Options:
  -h --help    Show this screen.`
const version = "0.1"
const default_port = ":50051"


func main() {
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		return
	}
	if arguments["server"].(bool) {
		lis, err := net.Listen("tcp", default_port)
		if err != nil {
			log.Fatalf("Unable to listen on %v")
		}
		s := grpc.NewServer()
		authz.RegisterAuthorizationServer(s, server.NewServer())
		reflection.Register(s)
		if err := s.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}
}
