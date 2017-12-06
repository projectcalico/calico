package nodeagentmgmt

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/colabsaumoh/proto-udsuspver/protos/mgmtintf_v1"
	mwi "github.com/colabsaumoh/proto-udsuspver/mgmtwlhintf"
)

type Server struct {
	wlmgmts     map[string]mwi.WorkloadMgmtInterface
	pathPrefix string
	done       chan bool //main 2 mgmt-api server to stop
	wli		*mwi.WlHandler
}

type Client struct {
	conn  *grpc.ClientConn
	dest  string
	isUds bool
}

func NewServer(pathPrefix string, wli *mwi.WlHandler) *Server {
	return &Server{
		done: make(chan bool, 1),
		pathPrefix: pathPrefix,
		wli: wli,
		wlmgmts: make(map[string]mwi.WorkloadMgmtInterface),
	}
}

func (s *Server) Stop() {
	s.done <- true
}

func (s *Server) WaitDone() {
	<-s.done
}

func (s *Server) Serve(isUds bool, path string) {
	grpcServer := grpc.NewServer()
	pb.RegisterNodeAgentMgmtServer(grpcServer, s)

	var lis net.Listener
	var err error
	if isUds == false {
		lis, err = net.Listen("tcp", path)
		if err != nil {
			log.Fatalf("failed to %v", err)
		}
	} else {
		_, e := os.Stat(path)
		if e == nil {
			e := os.RemoveAll(path)
			if e != nil {
				log.Fatalf("failed to %v %v", path, err)
			}
		}
		lis, err = net.Listen("unix", path)
		if err != nil {
			log.Fatalf("failed to %v", err)
		}
	}

	go func(ln net.Listener, s *Server) {
		<-s.done
		ln.Close()
		s.CloseAllWlds()
	}(lis, s)

	grpcServer.Serve(lis)
}

func (s *Server) WorkloadAdded(ctx context.Context, request *pb.WorkloadInfo) (*pb.Response, error) {

	log.Printf("%v", request)
	if _, ok := s.wlmgmts[request.Uid]; ok == true {
		status := &pb.Response_Status{Code: pb.Response_Status_ALREADY_EXISTS, Message: "Already present"}
		return &pb.Response{Status: status}, nil
	}

	s.wlmgmts[request.Uid] = s.wli.NewWlhCb(request, s.wli.Wl, s.pathPrefix)
	go s.wlmgmts[request.Uid].Serve()
	log.Printf("%v", s)

	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: "Ok"}
	return &pb.Response{Status: status}, nil
}

func (s *Server) WorkloadDeleted(ctx context.Context, request *pb.WorkloadInfo) (*pb.Response, error) {
	if _, ok := s.wlmgmts[request.Uid]; ok == false {
		status := &pb.Response_Status{Code: pb.Response_Status_NOT_FOUND, Message: "Not present"}
		return &pb.Response{Status: status}, nil
	}

	log.Printf("%s: Stop.", request.Uid)
	s.wlmgmts[request.Uid].Stop()
	s.wlmgmts[request.Uid].WaitDone()

	delete(s.wlmgmts, request.Uid)

	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: "Ok"}
	return &pb.Response{Status: status}, nil
}

func (s *Server) CloseAllWlds() {
	for _, wld := range s.wlmgmts {
		wld.Stop()
	}
	for _, wld := range s.wlmgmts {
		wld.WaitDone()
	}
}

func unixDialer(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", target, timeout)
}


// Used by the flexvolume driver to interface with the nodeagement mgmt grpc server
func NewClient(isUds bool, path string) *Client {
	c := new(Client)
	c.dest = path
	c.isUds = isUds
	return c
}

func ClientUds(path string) *Client {
	return NewClient(true, path)
}

func (c *Client) client() (pb.NodeAgentMgmtClient, error) {

	var conn *grpc.ClientConn
	var err error
	var opts []grpc.DialOption

	opts = append(opts, grpc.WithInsecure())
	if c.isUds == false {
		conn, err = grpc.Dial(c.dest, opts...)
		if err != nil {
			return nil, err
		}
	} else {
		opts = append(opts, grpc.WithDialer(unixDialer))
		conn, err = grpc.Dial(c.dest, opts...)
		if err != nil {
			return nil, err
		}
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(conn *grpc.ClientConn, c chan os.Signal) {
		<-c
		conn.Close()
		os.Exit(0)
	}(conn, sigc)

	c.conn = conn
	return pb.NewNodeAgentMgmtClient(conn), nil
}

func (c *Client) WorkloadAdded(ninputs *pb.WorkloadInfo) (*pb.Response, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}

	return cl.WorkloadAdded(context.Background(), ninputs)
}

func (c *Client) WorkloadDeleted(ninputs *pb.WorkloadInfo) (*pb.Response, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}

	return cl.WorkloadDeleted(context.Background(), ninputs)
}

func (c *Client) Close() {
	if c.conn == nil {
		return
	}
	c.conn.Close()
}
