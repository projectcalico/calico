// Copyright (c) 2018 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workloadapi

import (
	"context"
	"fmt"
	"log"

	"github.com/projectcalico/calico/pod2daemon/binder"
	pb "github.com/projectcalico/calico/pod2daemon/proto"
)

type WlServer struct {
	pb.UnimplementedVerifyServer
}

func NewWlAPIServer() pb.VerifyServer {
	return &WlServer{}
}

func (s *WlServer) Check(ctx context.Context, request *pb.Request) (*pb.Response, error) {

	log.Printf("[%v]: %v Check called", s, request)
	// Get the caller's credentials from the context.
	creds, e := binder.CallerFromContext(ctx)
	if !e {
		resp := "Not able to get credentials"
		status := &pb.Response_Status{Code: pb.Response_Status_PERMISSION_DENIED, Message: resp}
		return &pb.Response{Status: status}, nil
	}

	log.Printf("Credentials are %v", creds)

	resp := fmt.Sprintf("all good to workload with service account %v", creds.ServiceAccount)
	status := &pb.Response_Status{Code: pb.Response_Status_OK, Message: resp}
	return &pb.Response{Status: status}, nil
}
