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
	wlapi "github.com/colabsaumoh/proto-udsuspver/workloadapi"
)

type Server struct {
	wlapis     map[string]*wlapi.Server
	pathPrefix string
	done       chan bool //main 2 mgmt-api server to stop
}

type Client struct {
	conn  *grpc.ClientConn
	dest  string
	isUds bool
}

func NewServer(pathPrefix string) *Server {
	s := new(Server)
	s.done = make(chan bool, 1)
	s.pathPrefix = pathPrefix
	s.wlapis = make(map[string]*wlapi.Server)
	return s
}

func (s *Server) Done() {
	s.done <- true
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

func (s *Server) AddListener(ctx context.Context, request *pb.WorkloadInfo) (*pb.Response, error) {

	log.Printf("%v", request)
	if _, ok := s.wlapis[request.Uid]; ok == true {
		status := &pb.Response_Status{Code: pb.Response_Status_ALREADY_EXISTS, Message: "Already present"}
		return &pb.Response{Status: status}, nil
	}

	s.wlapis[request.Uid] = wlapi.NewServer(request, s.pathPrefix)
	go s.wlapis[request.Uid].Serve()
	log.Printf("%v", s)

	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: "Ok"}
	return &pb.Response{Status: status}, nil
}

func (s *Server) DelListener(ctx context.Context, request *pb.WorkloadInfo) (*pb.Response, error) {
	if _, ok := s.wlapis[request.Uid]; ok == false {
		status := &pb.Response_Status{Code: pb.Response_Status_NOT_FOUND, Message: "Not present"}
		return &pb.Response{Status: status}, nil
	}

	s.wlapis[request.Uid].Done()
	delete(s.wlapis, request.Uid)

	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: "Ok"}
	return &pb.Response{Status: status}, nil
}

func (s *Server) CloseAllWlds() {
	for _, wld := range s.wlapis {
		wld.Done()
	}
}

func unixDialer(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", target, timeout)
}

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

func (c *Client) AddListener(ninputs *pb.WorkloadInfo) (*pb.Response, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}

	return cl.AddListener(context.Background(), ninputs)
}

func (c *Client) DelListener(ninputs *pb.WorkloadInfo) (*pb.Response, error) {
	cl, err := c.client()
	if err != nil {
		return nil, err
	}

	return cl.DelListener(context.Background(), ninputs)
}

func (c *Client) Close() {
	if c.conn == nil {
		return
	}
	c.conn.Close()
}
