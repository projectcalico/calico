package main

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	authz "tigera.io/dikastes/proto"
	"tigera.io/dikastes/server"

	"github.com/projectcalico/libcalico-go/lib/api"

	docopt "github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	spireauth "github.com/spiffe/spire/pkg/agent/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server [-t <token>|--kube <kubeconfig>] [options]
  dikastes client <namespace> <account> [--method <method>] [options]

Options:
  <namespace>            Service account namespace.
  <account>              Service account name.
  -h --help              Show this screen.
  -l --listen <port>     Unix domain socket path [default: /var/run/dikastes/dikastes.sock]
  -d --dial <target>     Target to dial. [default: localhost:50051]
  -k --kubernetes <api>  Kubernetes API Endpoint [default: https://kubernetes:443]
  -c --ca <ca>           Kubernetes CA Cert file [default: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt]
  -t --token <token>     Kubernetes API Token file [default: /var/run/secrets/kubernetes.io/serviceaccount/token]
  --kube <kubeconfig>    Path to kubeconfig.
  --debug             Log at Debug level.`
const version = "0.1"
const NODE_NAME_ENV = "K8S_NODENAME"

func main() {
	arguments, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		println(usage)
		return
	}
	if arguments["--debug"].(bool) {
		log.SetLevel(log.DebugLevel)
	}
	if arguments["server"].(bool) {
		runServer(arguments)
	} else if arguments["client"].(bool) {
		runClient(arguments)
	}
	return
}

func runServer(arguments map[string]interface{}) {
	lis, err := net.Listen("unix", arguments["--listen"].(string))
	if err != nil {
		log.WithFields(log.Fields{
			"listen": arguments["--listen"],
			"err":    err,
		}).Fatal("Unable to listen.")
	}
	defer lis.Close()
	if err != nil {
		log.Fatalf("Unable to listen on %v", arguments["--listen"])
	}
	gs := grpc.NewServer(grpc.Creds(spireauth.NewCredentials()))
	ds, err := server.NewServer(getConfig(arguments), getNodeName())
	if err != nil {
		log.Fatalf("Unable to start server %v", err)
	}
	authz.RegisterAuthorizationServer(gs, ds)
	reflection.Register(gs)

	// Run gRPC server on separate goroutine so we catch any signals and clean up the socket.
	go func() {
		if err := gs.Serve(lis); err != nil {
			log.Fatalf("failed to serve: %v", err)
		}
	}()

	// Use a buffered channel so we don't miss any signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Block until a signal is received.
	s := <-c
	log.Infof("Got signal:", s)
}

func getNodeName() string {
	nn, ok := os.LookupEnv(NODE_NAME_ENV)
	if !ok {
		log.Fatalf("Environment variable %v is required.", NODE_NAME_ENV)
	}
	return nn
}

func runClient(arguments map[string]interface{}) {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithDialer(getDialer("unix"))}
	conn, err := grpc.Dial(arguments["--dial"].(string), opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	client := authz.NewAuthorizationClient(conn)
	req := authz.Request{
		Subject: &authz.Request_Subject{
			ServiceAccount: arguments["<account>"].(string),
			Namespace:      arguments["<namespace>"].(string)}}
	if arguments["--method"].(bool) {
		req.Action = &authz.Request_Action{
			Http: &authz.HTTPRequest{
				Method: arguments["<method>"].(string),
			},
		}
	}
	resp, err := client.Check(context.Background(), &req)
	if err != nil {
		log.Fatalf("Failed %v", err)
	}
	log.Infof("Check response:\n %v", resp)
	return
}

func getDialer(proto string) func(string, time.Duration) (net.Conn, error) {
	return func(target string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(proto, target, timeout)
	}
}

func getConfig(arguments map[string]interface{}) api.CalicoAPIConfig {
	cfg := api.CalicoAPIConfig{
		Spec: api.CalicoAPIConfigSpec{
			DatastoreType: api.Kubernetes,
			KubeConfig:    api.KubeConfig{},
		},
	}
	if arguments["--kube"] != nil {
		cfg.Spec.KubeConfig.Kubeconfig = arguments["--kube"].(string)
	} else {
		token, err := ioutil.ReadFile(arguments["--token"].(string))
		if err != nil {
			log.Fatalf("Could not open token file %v. %v", arguments["--token"], err)
		}
		cfg.Spec.KubeConfig.K8sAPIToken = string(token)
		cfg.Spec.KubeConfig.K8sAPIEndpoint = arguments["--kubernetes"].(string)
		cfg.Spec.KubeConfig.K8sCAFile = arguments["--ca"].(string)
	}
	return cfg
}
