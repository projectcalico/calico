package workloadapi

import (
	"fmt"
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	mwi "github.com/colabsaumoh/proto-udsuspver/mgmtwlhintf"
	wlh "github.com/colabsaumoh/proto-udsuspver/workloadhandler"
	pb "github.com/colabsaumoh/proto-udsuspver/protos/udsver_v1"
)

const (
	socName string = "/server.sock"
)

type WlServer struct {}

func NewWlAPIServer() *mwi.WlServer {
	return &mwi.WlServer{
		SockFile: socName,
		RegAPI: RegisterGrpc,
	}
}

func RegisterGrpc(s *grpc.Server) {
	pb.RegisterVerifyServer(s, &WlServer{})
}

func (s *WlServer) Check(ctx context.Context, request *pb.Request) (*pb.Response, error) {

	log.Printf("[%v]: %v Check called", s, request)
	// Get the caller's credentials from the context.
	creds, e := wlh.CallerFromContext(ctx)
	if !e {
		resp := fmt.Sprint("Not able to get credentials")
		status := &pb.Response_Status{Code: pb.Response_Status_PERMISSION_DENIED, Message: resp}
		return &pb.Response{Status: status}, nil
	}

	log.Printf("Credentials are %v", creds)

	resp := fmt.Sprintf("all good to workload with service account %v", creds.ServiceAccount)
	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: resp}
	return &pb.Response{Status: status}, nil
}