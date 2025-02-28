// Code generated by mockery v2.52.2. DO NOT EDIT.

package mocks

import (
	context "context"

	metadata "google.golang.org/grpc/metadata"

	mock "github.com/stretchr/testify/mock"

	proto "github.com/projectcalico/calico/goldmane/proto"
)

// Flows_StreamClient is an autogenerated mock type for the Flows_StreamClient type
type Flows_StreamClient[Res any] struct {
	mock.Mock
}

type Flows_StreamClient_Expecter[Res any] struct {
	mock *mock.Mock
}

func (_m *Flows_StreamClient[Res]) EXPECT() *Flows_StreamClient_Expecter[Res] {
	return &Flows_StreamClient_Expecter[Res]{mock: &_m.Mock}
}

// CloseSend provides a mock function with no fields
func (_m *Flows_StreamClient[Res]) CloseSend() error {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for CloseSend")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Flows_StreamClient_CloseSend_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'CloseSend'
type Flows_StreamClient_CloseSend_Call[Res any] struct {
	*mock.Call
}

// CloseSend is a helper method to define mock.On call
func (_e *Flows_StreamClient_Expecter[Res]) CloseSend() *Flows_StreamClient_CloseSend_Call[Res] {
	return &Flows_StreamClient_CloseSend_Call[Res]{Call: _e.mock.On("CloseSend")}
}

func (_c *Flows_StreamClient_CloseSend_Call[Res]) Run(run func()) *Flows_StreamClient_CloseSend_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Flows_StreamClient_CloseSend_Call[Res]) Return(_a0 error) *Flows_StreamClient_CloseSend_Call[Res] {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Flows_StreamClient_CloseSend_Call[Res]) RunAndReturn(run func() error) *Flows_StreamClient_CloseSend_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// Context provides a mock function with no fields
func (_m *Flows_StreamClient[Res]) Context() context.Context {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Context")
	}

	var r0 context.Context
	if rf, ok := ret.Get(0).(func() context.Context); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(context.Context)
		}
	}

	return r0
}

// Flows_StreamClient_Context_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Context'
type Flows_StreamClient_Context_Call[Res any] struct {
	*mock.Call
}

// Context is a helper method to define mock.On call
func (_e *Flows_StreamClient_Expecter[Res]) Context() *Flows_StreamClient_Context_Call[Res] {
	return &Flows_StreamClient_Context_Call[Res]{Call: _e.mock.On("Context")}
}

func (_c *Flows_StreamClient_Context_Call[Res]) Run(run func()) *Flows_StreamClient_Context_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Flows_StreamClient_Context_Call[Res]) Return(_a0 context.Context) *Flows_StreamClient_Context_Call[Res] {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Flows_StreamClient_Context_Call[Res]) RunAndReturn(run func() context.Context) *Flows_StreamClient_Context_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// Header provides a mock function with no fields
func (_m *Flows_StreamClient[Res]) Header() (metadata.MD, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Header")
	}

	var r0 metadata.MD
	var r1 error
	if rf, ok := ret.Get(0).(func() (metadata.MD, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() metadata.MD); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(metadata.MD)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Flows_StreamClient_Header_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Header'
type Flows_StreamClient_Header_Call[Res any] struct {
	*mock.Call
}

// Header is a helper method to define mock.On call
func (_e *Flows_StreamClient_Expecter[Res]) Header() *Flows_StreamClient_Header_Call[Res] {
	return &Flows_StreamClient_Header_Call[Res]{Call: _e.mock.On("Header")}
}

func (_c *Flows_StreamClient_Header_Call[Res]) Run(run func()) *Flows_StreamClient_Header_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Flows_StreamClient_Header_Call[Res]) Return(_a0 metadata.MD, _a1 error) *Flows_StreamClient_Header_Call[Res] {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Flows_StreamClient_Header_Call[Res]) RunAndReturn(run func() (metadata.MD, error)) *Flows_StreamClient_Header_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// Recv provides a mock function with no fields
func (_m *Flows_StreamClient[Res]) Recv() (*proto.FlowResult, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Recv")
	}

	var r0 *proto.FlowResult
	var r1 error
	if rf, ok := ret.Get(0).(func() (*proto.FlowResult, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() *proto.FlowResult); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*proto.FlowResult)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Flows_StreamClient_Recv_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Recv'
type Flows_StreamClient_Recv_Call[Res any] struct {
	*mock.Call
}

// Recv is a helper method to define mock.On call
func (_e *Flows_StreamClient_Expecter[Res]) Recv() *Flows_StreamClient_Recv_Call[Res] {
	return &Flows_StreamClient_Recv_Call[Res]{Call: _e.mock.On("Recv")}
}

func (_c *Flows_StreamClient_Recv_Call[Res]) Run(run func()) *Flows_StreamClient_Recv_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Flows_StreamClient_Recv_Call[Res]) Return(_a0 *proto.FlowResult, _a1 error) *Flows_StreamClient_Recv_Call[Res] {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *Flows_StreamClient_Recv_Call[Res]) RunAndReturn(run func() (*proto.FlowResult, error)) *Flows_StreamClient_Recv_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// RecvMsg provides a mock function with given fields: m
func (_m *Flows_StreamClient[Res]) RecvMsg(m any) error {
	ret := _m.Called(m)

	if len(ret) == 0 {
		panic("no return value specified for RecvMsg")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(m)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Flows_StreamClient_RecvMsg_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RecvMsg'
type Flows_StreamClient_RecvMsg_Call[Res any] struct {
	*mock.Call
}

// RecvMsg is a helper method to define mock.On call
//   - m any
func (_e *Flows_StreamClient_Expecter[Res]) RecvMsg(m interface{}) *Flows_StreamClient_RecvMsg_Call[Res] {
	return &Flows_StreamClient_RecvMsg_Call[Res]{Call: _e.mock.On("RecvMsg", m)}
}

func (_c *Flows_StreamClient_RecvMsg_Call[Res]) Run(run func(m any)) *Flows_StreamClient_RecvMsg_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(any))
	})
	return _c
}

func (_c *Flows_StreamClient_RecvMsg_Call[Res]) Return(_a0 error) *Flows_StreamClient_RecvMsg_Call[Res] {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Flows_StreamClient_RecvMsg_Call[Res]) RunAndReturn(run func(any) error) *Flows_StreamClient_RecvMsg_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// SendMsg provides a mock function with given fields: m
func (_m *Flows_StreamClient[Res]) SendMsg(m any) error {
	ret := _m.Called(m)

	if len(ret) == 0 {
		panic("no return value specified for SendMsg")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(any) error); ok {
		r0 = rf(m)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Flows_StreamClient_SendMsg_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'SendMsg'
type Flows_StreamClient_SendMsg_Call[Res any] struct {
	*mock.Call
}

// SendMsg is a helper method to define mock.On call
//   - m any
func (_e *Flows_StreamClient_Expecter[Res]) SendMsg(m interface{}) *Flows_StreamClient_SendMsg_Call[Res] {
	return &Flows_StreamClient_SendMsg_Call[Res]{Call: _e.mock.On("SendMsg", m)}
}

func (_c *Flows_StreamClient_SendMsg_Call[Res]) Run(run func(m any)) *Flows_StreamClient_SendMsg_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(any))
	})
	return _c
}

func (_c *Flows_StreamClient_SendMsg_Call[Res]) Return(_a0 error) *Flows_StreamClient_SendMsg_Call[Res] {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Flows_StreamClient_SendMsg_Call[Res]) RunAndReturn(run func(any) error) *Flows_StreamClient_SendMsg_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// Trailer provides a mock function with no fields
func (_m *Flows_StreamClient[Res]) Trailer() metadata.MD {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Trailer")
	}

	var r0 metadata.MD
	if rf, ok := ret.Get(0).(func() metadata.MD); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(metadata.MD)
		}
	}

	return r0
}

// Flows_StreamClient_Trailer_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Trailer'
type Flows_StreamClient_Trailer_Call[Res any] struct {
	*mock.Call
}

// Trailer is a helper method to define mock.On call
func (_e *Flows_StreamClient_Expecter[Res]) Trailer() *Flows_StreamClient_Trailer_Call[Res] {
	return &Flows_StreamClient_Trailer_Call[Res]{Call: _e.mock.On("Trailer")}
}

func (_c *Flows_StreamClient_Trailer_Call[Res]) Run(run func()) *Flows_StreamClient_Trailer_Call[Res] {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *Flows_StreamClient_Trailer_Call[Res]) Return(_a0 metadata.MD) *Flows_StreamClient_Trailer_Call[Res] {
	_c.Call.Return(_a0)
	return _c
}

func (_c *Flows_StreamClient_Trailer_Call[Res]) RunAndReturn(run func() metadata.MD) *Flows_StreamClient_Trailer_Call[Res] {
	_c.Call.Return(run)
	return _c
}

// NewFlows_StreamClient creates a new instance of Flows_StreamClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewFlows_StreamClient[Res any](t interface {
	mock.TestingT
	Cleanup(func())
}) *Flows_StreamClient[Res] {
	mock := &Flows_StreamClient[Res]{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
