package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"tigera.io/dikastes/proto"
	"tigera.io/dikastes/server"

	"context"
	docopt "github.com/docopt/docopt-go"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/apimachinery/pkg/util/validation"
	"time"
)

const usage = `Dikastes - the decider.

Usage:
  dikastes server <path> [options]
  dikastes client [options]

Options:
  <path>              Path to file with pod labels.
  -h --help           Show this screen.
  -l --listen <port>  IP/port to listen on. [default: :50051]
  -s --socket <sock>  Type of socket [default: tcp]
  -d --dial <target>  Target to dial. [default: localhost:50051]
  --debug             Log at Debug level.`
const version = "0.1"

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
	labels, err := parseLabels(arguments["<path>"].(string))
	if err != nil {
		log.Fatalf("Unable to load labels. %v", err)
	}
	lis, err := net.Listen(arguments["--socket"].(string), arguments["--listen"].(string))
	defer lis.Close()
	if err != nil {
		log.Fatalf("Unable to listen on %v", arguments["--listen"])
	}
	gs := grpc.NewServer()
	ds, err := server.NewServer(labels)
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

// Parse labels in the form key=value and return a map.
// Based on https://github.com/kubernetes/kubernetes/blob/master/pkg/kubectl/cmd/label.go
func parseLabels(path string) (map[string]string, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, err
	}
	labels := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		labelSpec := scanner.Text()
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return labels, nil
}

func runClient(arguments map[string]interface{}) {
	opts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithDialer(getDialer(arguments["--socket"].(string)))}
	conn, err := grpc.Dial(arguments["--dial"].(string), opts...)
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

func getDialer(proto string) func(string, time.Duration) (net.Conn, error) {
	return func(target string, timeout time.Duration) (net.Conn, error) {
		return net.DialTimeout(proto, target, timeout)
	}
}
