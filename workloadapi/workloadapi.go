package workloadapi

import (
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	nam "github.com/colabsaumoh/proto-udsuspver/nodeagentmgmt"
	pbmgmt "github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1"
	pb "github.com/colabsaumoh/proto-udsuspver/protos/udsver_v1"
)

const (
	socName string = "/server.sock"
)

type Server struct {
	c              int
	Uid            string
	Name           string
	Namespace      string
	ServiceAccount string
	SockFile       string
	done           chan bool
}

func NewServer(wli *pbmgmt.WorkloadInfo, pathPrefix string) nam.WorkloadMgmtInterface {
	s := &Server{
		done: make(chan bool, 1),
		Uid: wli.Uid,
		Name: wli.Workload,
		Namespace: wli.Namespace,
		ServiceAccount: wli.Serviceaccount,
		SockFile: pathPrefix + "/" + wli.Uid + socName,
	}
	return s
}

func (s *Server) Check(ctx context.Context, request *pb.Request) (*pb.Response, error) {
	var r string
	var e bool
	r = "permit"
	e = true

	log.Printf("[%v]: %v Check called, resp: %v", s, request, r)
	resp := fmt.Sprintf("all good %v to %v", s.c, s.ServiceAccount)
	s.c += 1
	if e == false {
		status := &pb.Response_Status{Code: pb.Response_Status_PERMISSION_DENIED, Message: resp}
		return &pb.Response{Status: status}, nil
	}
	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: resp}
	return &pb.Response{Status: status}, nil
}

// WorkloadApi adherence to nodeagent workload management interface.
func (s *Server) Serve() {
	grpcServer := grpc.NewServer()
	pb.RegisterVerifyServer(grpcServer, s)

	var lis net.Listener
	var err error
	_, e := os.Stat(s.SockFile)
	if e == nil {
		e := os.RemoveAll(s.SockFile)
		if e != nil {
			log.Printf("Failed to rm %v (%v)", s.SockFile, e)
			return
		}
	}

	lis, err = net.Listen("unix", s.SockFile)
	if err != nil {
		log.Printf("failed to %v", err)
		return
	}

	go func(ln net.Listener, c chan bool) {
		<-c
		ln.Close()
		log.Printf("Closed the listener.")
		c <- true
	}(lis, s.done)

	log.Printf("workload [%v] listen", s)
	grpcServer.Serve(lis)
}

// Tell the server it should stop
func (s *Server) Stop() {
	s.done <- true
}

// Wait for the server to stop and then return
func (s *Server) WaitDone() {
	<-s.done
}
