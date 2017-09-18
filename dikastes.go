package main

import (
	"fmt"
	"net"
	"strings"

	"tigera.io/dikastes/proto"
	"tigera.io/dikastes/server"

	"context"
	docopt "github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/util/validation"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server <label>... [options]
  dikastes client [options]

Options:
  -h --help    Show this screen.`
const version = "0.1"
const default_port = ":50051"

func main() {
	log.SetLevel(log.DebugLevel)
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		return
	}
	if arguments["server"].(bool) {
		runServer(arguments)
	} else if arguments["client"].(bool) {
		runClient()
	}
	return
}

func runServer(arguments map[string]interface{}) {
	labels, err := parseLabels(arguments["<label>"].([]string))
	if err != nil {
		println(usage)
		fmt.Printf("Invalid <label> format: %v", err)
	}
	lis, err := net.Listen("tcp", default_port)
	if err != nil {
		log.Fatalf("Unable to listen on %v")
	}
	gs := grpc.NewServer()
	ds, err := server.NewServer(labels)
	if err != nil {
		log.Fatalf("Unable to start server %v", err)
	}
	authz.RegisterAuthorizationServer(gs, ds)
	reflection.Register(gs)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Parse labels in the form key=value and return a map.
// Based on https://github.com/kubernetes/kubernetes/blob/master/pkg/kubectl/cmd/label.go
func parseLabels(spec []string) (map[string]string, error) {
	labels := map[string]string{}
	for _, labelSpec := range spec {
		if strings.Contains(labelSpec, "=") {
			parts := strings.Split(labelSpec, "=")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid label spec: %v", labelSpec)
			}
			if errs := validation.IsValidLabelValue(parts[1]); len(errs) != 0 {
				return nil, fmt.Errorf("invalid label value: %q: %s", labelSpec, strings.Join(errs, ";"))
			}
			labels[parts[0]] = parts[1]
		} else {
			return nil, fmt.Errorf("unknown label spec: %v", labelSpec)
		}
	}
	return labels, nil
}

func runClient() {
	opts := []grpc.DialOption{grpc.WithInsecure()}
	conn, err := grpc.Dial("127.0.0.1:50051", opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := authz.NewAuthorizationClient(conn)
	req := authz.Request{
		Subject: &authz.Request_Subject{
			ServiceAccount: "spike"}}
	resp, err := client.Check(context.Background(), &req)
	if err != nil {
		log.Fatalf("Failed %v", err)
	}
	log.Infof("Check response:\n %v", resp)
	return
}
