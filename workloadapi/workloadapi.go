package workloadapi

import (
        "fmt"
	"log"
	"net"
	"os"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

        pb "github.com/colabsaumoh/proto-udsuspver/udsver_v1"
)

const (
	socName	string = "/server.sock"
)

type Server struct {
	c		int
        Uid             string
        Name            string
        Namespace	string
        ServiceAccount  string
	SockFile	string
	done		chan bool
}

func NewServer(wli *pb.WorkloadInfo, pathPrefix string) *Server {
	s := new(Server)
	s.done = make(chan bool, 1)

	s.Uid = wli.Uid
	s.Name = wli.Workload
	s.Namespace = wli.Namespace
	s.ServiceAccount = wli.Serviceaccount
	s.SockFile = pathPrefix + "/" + s.Uid + socName
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
		status := &pb.Response_Status{Code: pb.Response_Status_PERMISSION_DENIED, Message: resp }
		return &pb.Response{Status: status}, nil
        }
	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: resp}
	return &pb.Response{Status: status}, nil
}

func (s *Server) Serve() error {
	grpcServer := grpc.NewServer()
	pb.RegisterVerifyServer(grpcServer, s)

	var lis net.Listener
	var err error
        _, e := os.Stat(s.SockFile)
        if e == nil {
		e := os.RemoveAll(s.SockFile)
		if e != nil {
			log.Printf("Failed to rm %v (%v)", s.SockFile, e)
			return e
                }
	}

	lis, err = net.Listen("unix", s.SockFile)
	if err != nil {
		log.Printf("failed to %v", err)
		return e
	}


	go func(ln net.Listener, c chan bool) {
		<-c
		ln.Close()
	}(lis, s.done)

	log.Printf("workload [%v] listen", s)
	grpcServer.Serve(lis)
	return nil
}

func (s *Server) Done() {
	s.done <- true
}
