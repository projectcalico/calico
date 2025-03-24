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
	Flows_List_FullMethodName        = "/goldmane.Flows/List"
	Flows_Stream_FullMethodName      = "/goldmane.Flows/Stream"
	Flows_FilterHints_FullMethodName = "/goldmane.Flows/FilterHints"
)

// FlowsClient is the client API for Flows service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Flows provides APIs for querying aggregated Flow data.
//
// The returned Flows will be aggregated across cluster nodes, as well as the specified aggregation
// time interval.
type FlowsClient interface {
	// List is an API call to query for one or more Flows.
	List(ctx context.Context, in *FlowListRequest, opts ...grpc.CallOption) (*FlowListResult, error)
	// Stream is an API call to return a long running stream of new Flows as they are generated.
	Stream(ctx context.Context, in *FlowStreamRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[FlowResult], error)
	// FilterHints can be used to discover available filter criteria, such as
	// Namespaces and source / destination names. It allows progressive filtering of criteria based on
	// other filters. i.e., return the flow destinations given a source namespace.
	// Note that this API provides hints to the UI based on past flows and other values may be valid.
	FilterHints(ctx context.Context, in *FilterHintsRequest, opts ...grpc.CallOption) (*FilterHintsResult, error)
}

type flowsClient struct {
	cc grpc.ClientConnInterface
}

func NewFlowsClient(cc grpc.ClientConnInterface) FlowsClient {
	return &flowsClient{cc}
}

func (c *flowsClient) List(ctx context.Context, in *FlowListRequest, opts ...grpc.CallOption) (*FlowListResult, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FlowListResult)
	err := c.cc.Invoke(ctx, Flows_List_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *flowsClient) Stream(ctx context.Context, in *FlowStreamRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[FlowResult], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Flows_ServiceDesc.Streams[0], Flows_Stream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[FlowStreamRequest, FlowResult]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Flows_StreamClient = grpc.ServerStreamingClient[FlowResult]

func (c *flowsClient) FilterHints(ctx context.Context, in *FilterHintsRequest, opts ...grpc.CallOption) (*FilterHintsResult, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(FilterHintsResult)
	err := c.cc.Invoke(ctx, Flows_FilterHints_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FlowsServer is the server API for Flows service.
// All implementations must embed UnimplementedFlowsServer
// for forward compatibility.
//
// Flows provides APIs for querying aggregated Flow data.
//
// The returned Flows will be aggregated across cluster nodes, as well as the specified aggregation
// time interval.
type FlowsServer interface {
	// List is an API call to query for one or more Flows.
	List(context.Context, *FlowListRequest) (*FlowListResult, error)
	// Stream is an API call to return a long running stream of new Flows as they are generated.
	Stream(*FlowStreamRequest, grpc.ServerStreamingServer[FlowResult]) error
	// FilterHints can be used to discover available filter criteria, such as
	// Namespaces and source / destination names. It allows progressive filtering of criteria based on
	// other filters. i.e., return the flow destinations given a source namespace.
	// Note that this API provides hints to the UI based on past flows and other values may be valid.
	FilterHints(context.Context, *FilterHintsRequest) (*FilterHintsResult, error)
	mustEmbedUnimplementedFlowsServer()
}

// UnimplementedFlowsServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedFlowsServer struct{}

func (UnimplementedFlowsServer) List(context.Context, *FlowListRequest) (*FlowListResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedFlowsServer) Stream(*FlowStreamRequest, grpc.ServerStreamingServer[FlowResult]) error {
	return status.Errorf(codes.Unimplemented, "method Stream not implemented")
}
func (UnimplementedFlowsServer) FilterHints(context.Context, *FilterHintsRequest) (*FilterHintsResult, error) {
	return nil, status.Errorf(codes.Unimplemented, "method FilterHints not implemented")
}
func (UnimplementedFlowsServer) mustEmbedUnimplementedFlowsServer() {}
func (UnimplementedFlowsServer) testEmbeddedByValue()               {}

// UnsafeFlowsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to FlowsServer will
// result in compilation errors.
type UnsafeFlowsServer interface {
	mustEmbedUnimplementedFlowsServer()
}

func RegisterFlowsServer(s grpc.ServiceRegistrar, srv FlowsServer) {
	// If the following call pancis, it indicates UnimplementedFlowsServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Flows_ServiceDesc, srv)
}

func _Flows_List_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FlowListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowsServer).List(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Flows_List_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowsServer).List(ctx, req.(*FlowListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Flows_Stream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(FlowStreamRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(FlowsServer).Stream(m, &grpc.GenericServerStream[FlowStreamRequest, FlowResult]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Flows_StreamServer = grpc.ServerStreamingServer[FlowResult]

func _Flows_FilterHints_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FilterHintsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(FlowsServer).FilterHints(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Flows_FilterHints_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(FlowsServer).FilterHints(ctx, req.(*FilterHintsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Flows_ServiceDesc is the grpc.ServiceDesc for Flows service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Flows_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "goldmane.Flows",
	HandlerType: (*FlowsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "List",
			Handler:    _Flows_List_Handler,
		},
		{
			MethodName: "FilterHints",
			Handler:    _Flows_FilterHints_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Stream",
			Handler:       _Flows_Stream_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "api.proto",
}

const (
	FlowCollector_Connect_FullMethodName = "/goldmane.FlowCollector/Connect"
)

// FlowCollectorClient is the client API for FlowCollector service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// FlowCollector provides APIs capable of receiving streams of Flow data from cluster nodes.
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
// FlowCollector provides APIs capable of receiving streams of Flow data from cluster nodes.
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
	ServiceName: "goldmane.FlowCollector",
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

const (
	Statistics_List_FullMethodName = "/goldmane.Statistics/List"
)

// StatisticsClient is the client API for Statistics service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Statistics provides APIs for retrieving Flow statistics.
type StatisticsClient interface {
	// List returns statistics data for the given request. One StatisticsResult will be returned for
	// each matching PolicyHit and direction over the timeframe, containing time-series data covering the
	// provided time range.
	List(ctx context.Context, in *StatisticsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[StatisticsResult], error)
}

type statisticsClient struct {
	cc grpc.ClientConnInterface
}

func NewStatisticsClient(cc grpc.ClientConnInterface) StatisticsClient {
	return &statisticsClient{cc}
}

func (c *statisticsClient) List(ctx context.Context, in *StatisticsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[StatisticsResult], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &Statistics_ServiceDesc.Streams[0], Statistics_List_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[StatisticsRequest, StatisticsResult]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Statistics_ListClient = grpc.ServerStreamingClient[StatisticsResult]

// StatisticsServer is the server API for Statistics service.
// All implementations must embed UnimplementedStatisticsServer
// for forward compatibility.
//
// Statistics provides APIs for retrieving Flow statistics.
type StatisticsServer interface {
	// List returns statistics data for the given request. One StatisticsResult will be returned for
	// each matching PolicyHit and direction over the timeframe, containing time-series data covering the
	// provided time range.
	List(*StatisticsRequest, grpc.ServerStreamingServer[StatisticsResult]) error
	mustEmbedUnimplementedStatisticsServer()
}

// UnimplementedStatisticsServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedStatisticsServer struct{}

func (UnimplementedStatisticsServer) List(*StatisticsRequest, grpc.ServerStreamingServer[StatisticsResult]) error {
	return status.Errorf(codes.Unimplemented, "method List not implemented")
}
func (UnimplementedStatisticsServer) mustEmbedUnimplementedStatisticsServer() {}
func (UnimplementedStatisticsServer) testEmbeddedByValue()                    {}

// UnsafeStatisticsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to StatisticsServer will
// result in compilation errors.
type UnsafeStatisticsServer interface {
	mustEmbedUnimplementedStatisticsServer()
}

func RegisterStatisticsServer(s grpc.ServiceRegistrar, srv StatisticsServer) {
	// If the following call pancis, it indicates UnimplementedStatisticsServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Statistics_ServiceDesc, srv)
}

func _Statistics_List_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(StatisticsRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(StatisticsServer).List(m, &grpc.GenericServerStream[StatisticsRequest, StatisticsResult]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type Statistics_ListServer = grpc.ServerStreamingServer[StatisticsResult]

// Statistics_ServiceDesc is the grpc.ServiceDesc for Statistics service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Statistics_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "goldmane.Statistics",
	HandlerType: (*StatisticsServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "List",
			Handler:       _Statistics_List_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "api.proto",
}
