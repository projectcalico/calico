// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.5.0
// source: api.proto

package proto

import (
	context "context"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	FlowAPI_List_FullMethodName   = "/felix.FlowAPI/List"
	FlowAPI_Stream_FullMethodName = "/felix.FlowAPI/Stream"
)

// FlowAPIClient is the client API for FlowAPI service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type FlowAPIClient interface {
	// List is an API call to query for one or more Flows.
	// Matching Flows are streamed back to the caller.
	List(ctx context.Context, in *FlowRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Flow], error)
	Stream(ctx context.Context, in *FlowRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Flow], error)
}

type flowAPIClient struct {
	cc grpc.ClientConnInterface
}

func NewFlowAPIClient(cc grpc.ClientConnInterface) FlowAPIClient {
	return &flowAPIClient{cc}
}

func (c *flowAPIClient) List(ctx context.Context, in *FlowRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Flow], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &FlowAPI_ServiceDesc.Streams[0], FlowAPI_List_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[FlowRequest, Flow]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowAPI_ListClient = grpc.ServerStreamingClient[Flow]

func (c *flowAPIClient) Stream(ctx context.Context, in *FlowRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Flow], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &FlowAPI_ServiceDesc.Streams[1], FlowAPI_Stream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[FlowRequest, Flow]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowAPI_StreamClient = grpc.ServerStreamingClient[Flow]

// FlowAPIServer is the server API for FlowAPI service.
// All implementations must embed UnimplementedFlowAPIServer
// for forward compatibility.
type FlowAPIServer interface {
	// List is an API call to query for one or more Flows.
	// Matching Flows are streamed back to the caller.
	List(*FlowRequest, grpc.ServerStreamingServer[Flow]) error
	Stream(*FlowRequest, grpc.ServerStreamingServer[Flow]) error
	mustEmbedUnimplementedFlowAPIServer()
}

// UnimplementedFlowAPIServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedFlowAPIServer struct{}

func (UnimplementedFlowAPIServer) List(*FlowRequest, grpc.ServerStreamingServer[Flow]) error {
	return status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedFlowAPIServer) Stream(*FlowRequest, grpc.ServerStreamingServer[Flow]) error {
	return status.Errorf(codes.Unimplemented, "method Stream not implemented")
}
func (UnimplementedFlowAPIServer) mustEmbedUnimplementedFlowAPIServer() {}
func (UnimplementedFlowAPIServer) testEmbeddedByValue()                 {}

// UnsafeFlowAPIServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FlowAPIServer will
// result in compilation errors.
type UnsafeFlowAPIServer interface {
	mustEmbedUnimplementedFlowAPIServer()
}

func RegisterFlowAPIServer(s grpc.ServiceRegistrar, srv FlowAPIServer) {
	// If the following call pancis, it indicates UnimplementedFlowAPIServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&FlowAPI_ServiceDesc, srv)
}

func _FlowAPI_List_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(FlowRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowAPIServer).List(m, &grpc.GenericServerStream[FlowRequest, Flow]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowAPI_ListServer = grpc.ServerStreamingServer[Flow]

func _FlowAPI_Stream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(FlowRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowAPIServer).Stream(m, &grpc.GenericServerStream[FlowRequest, Flow]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowAPI_StreamServer = grpc.ServerStreamingServer[Flow]

// FlowAPI_ServiceDesc is the grpc.ServiceDesc for FlowAPI service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var FlowAPI_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "felix.FlowAPI",
	HandlerType: (*FlowAPIServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "List",
			Handler:       _FlowAPI_List_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "Stream",
			Handler:       _FlowAPI_Stream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "api.proto",
}

const (
	FlowCollector_Connect_FullMethodName = "/felix.FlowCollector/Connect"
)

// FlowCollectorClient is the client API for FlowCollector service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// FlowCollector represents an API capable of receiving streams of Flow data
// from cluster nodes.
type FlowCollectorClient interface {
	// Connect receives a connection that may stream one or more FlowUpdates. A FlowReceipt is returned
	// to the client by the server after each FlowUpdate.
	//
	// Following a connection or reconnection to the server, clients should duplicates of previously transmitted FlowsUpdates
	// in order to allow the server to rebuild its cache, as well as any new FlowUpdates that have not previously been transmitted.
	// The server is responsible for deduplicating where needed.
	Connect(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[FlowUpdate, FlowReceipt], error)
}

type flowCollectorClient struct {
	cc grpc.ClientConnInterface
}

func NewFlowCollectorClient(cc grpc.ClientConnInterface) FlowCollectorClient {
	return &flowCollectorClient{cc}
}

func (c *flowCollectorClient) Connect(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[FlowUpdate, FlowReceipt], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &FlowCollector_ServiceDesc.Streams[0], FlowCollector_Connect_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[FlowUpdate, FlowReceipt]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowCollector_ConnectClient = grpc.BidiStreamingClient[FlowUpdate, FlowReceipt]

// FlowCollectorServer is the server API for FlowCollector service.
// All implementations must embed UnimplementedFlowCollectorServer
// for forward compatibility.
//
// FlowCollector represents an API capable of receiving streams of Flow data
// from cluster nodes.
type FlowCollectorServer interface {
	// Connect receives a connection that may stream one or more FlowUpdates. A FlowReceipt is returned
	// to the client by the server after each FlowUpdate.
	//
	// Following a connection or reconnection to the server, clients should duplicates of previously transmitted FlowsUpdates
	// in order to allow the server to rebuild its cache, as well as any new FlowUpdates that have not previously been transmitted.
	// The server is responsible for deduplicating where needed.
	Connect(grpc.BidiStreamingServer[FlowUpdate, FlowReceipt]) error
	mustEmbedUnimplementedFlowCollectorServer()
}

// UnimplementedFlowCollectorServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedFlowCollectorServer struct{}

func (UnimplementedFlowCollectorServer) Connect(grpc.BidiStreamingServer[FlowUpdate, FlowReceipt]) error {
	return status.Errorf(codes.Unimplemented, "method Connect not implemented")
}
func (UnimplementedFlowCollectorServer) mustEmbedUnimplementedFlowCollectorServer() {}
func (UnimplementedFlowCollectorServer) testEmbeddedByValue()                       {}

// UnsafeFlowCollectorServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FlowCollectorServer will
// result in compilation errors.
type UnsafeFlowCollectorServer interface {
	mustEmbedUnimplementedFlowCollectorServer()
}

func RegisterFlowCollectorServer(s grpc.ServiceRegistrar, srv FlowCollectorServer) {
	// If the following call pancis, it indicates UnimplementedFlowCollectorServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&FlowCollector_ServiceDesc, srv)
}

func _FlowCollector_Connect_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(FlowCollectorServer).Connect(&grpc.GenericServerStream[FlowUpdate, FlowReceipt]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type FlowCollector_ConnectServer = grpc.BidiStreamingServer[FlowUpdate, FlowReceipt]

// FlowCollector_ServiceDesc is the grpc.ServiceDesc for FlowCollector service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var FlowCollector_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "felix.FlowCollector",
	HandlerType: (*FlowCollectorServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Connect",
			Handler:       _FlowCollector_Connect_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "api.proto",
}
