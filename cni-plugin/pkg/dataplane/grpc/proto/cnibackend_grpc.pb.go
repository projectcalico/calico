// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.2
// source: cnibackend.proto

package proto

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	CniDataplane_Add_FullMethodName = "/cni.CniDataplane/Add"
	CniDataplane_Del_FullMethodName = "/cni.CniDataplane/Del"
)

// CniDataplaneClient is the client API for CniDataplane service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CniDataplaneClient interface {
	Add(ctx context.Context, in *AddRequest, opts ...grpc.CallOption) (*AddReply, error)
	Del(ctx context.Context, in *DelRequest, opts ...grpc.CallOption) (*DelReply, error)
}

type cniDataplaneClient struct {
	cc grpc.ClientConnInterface
}

func NewCniDataplaneClient(cc grpc.ClientConnInterface) CniDataplaneClient {
	return &cniDataplaneClient{cc}
}

func (c *cniDataplaneClient) Add(ctx context.Context, in *AddRequest, opts ...grpc.CallOption) (*AddReply, error) {
	out := new(AddReply)
	err := c.cc.Invoke(ctx, CniDataplane_Add_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *cniDataplaneClient) Del(ctx context.Context, in *DelRequest, opts ...grpc.CallOption) (*DelReply, error) {
	out := new(DelReply)
	err := c.cc.Invoke(ctx, CniDataplane_Del_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CniDataplaneServer is the server API for CniDataplane service.
// All implementations must embed UnimplementedCniDataplaneServer
// for forward compatibility
type CniDataplaneServer interface {
	Add(context.Context, *AddRequest) (*AddReply, error)
	Del(context.Context, *DelRequest) (*DelReply, error)
	mustEmbedUnimplementedCniDataplaneServer()
}

// UnimplementedCniDataplaneServer must be embedded to have forward compatible implementations.
type UnimplementedCniDataplaneServer struct {
}

func (UnimplementedCniDataplaneServer) Add(context.Context, *AddRequest) (*AddReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Add not implemented")
}
func (UnimplementedCniDataplaneServer) Del(context.Context, *DelRequest) (*DelReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Del not implemented")
}
func (UnimplementedCniDataplaneServer) mustEmbedUnimplementedCniDataplaneServer() {}

// UnsafeCniDataplaneServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CniDataplaneServer will
// result in compilation errors.
type UnsafeCniDataplaneServer interface {
	mustEmbedUnimplementedCniDataplaneServer()
}

func RegisterCniDataplaneServer(s grpc.ServiceRegistrar, srv CniDataplaneServer) {
	s.RegisterService(&CniDataplane_ServiceDesc, srv)
}

func _CniDataplane_Add_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CniDataplaneServer).Add(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CniDataplane_Add_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CniDataplaneServer).Add(ctx, req.(*AddRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _CniDataplane_Del_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CniDataplaneServer).Del(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: CniDataplane_Del_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CniDataplaneServer).Del(ctx, req.(*DelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// CniDataplane_ServiceDesc is the grpc.ServiceDesc for CniDataplane service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var CniDataplane_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "cni.CniDataplane",
	HandlerType: (*CniDataplaneServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Add",
			Handler:    _CniDataplane_Add_Handler,
		},
		{
			MethodName: "Del",
			Handler:    _CniDataplane_Del_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "cnibackend.proto",
}
