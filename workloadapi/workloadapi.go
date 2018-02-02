package workloadapi

import (
	"fmt"
	"log"

	"golang.org/x/net/context"

	"github.com/colabsaumoh/proto-udsuspver/binder"
	pb "github.com/colabsaumoh/proto-udsuspver/protos/udsver_v1"
)

type WlServer struct{}

func NewWlAPIServer() pb.VerifyServer {
	return &WlServer{}
}

func (s *WlServer) Check(ctx context.Context, request *pb.Request) (*pb.Response, error) {

	log.Printf("[%v]: %v Check called", s, request)
	// Get the caller's credentials from the context.
	creds, e := binder.CallerFromContext(ctx)
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
