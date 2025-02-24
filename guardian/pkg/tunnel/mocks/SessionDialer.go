// Code generated by mockery v2.50.4. DO NOT EDIT.

package mocks

import (
	mock "github.com/stretchr/testify/mock"

	tunnel "github.com/projectcalico/calico/guardian/pkg/tunnel"
)

// SessionDialer is an autogenerated mock type for the SessionDialer type
type SessionDialer struct {
	mock.Mock
}

// Dial provides a mock function with no fields
func (_m *SessionDialer) Dial() (tunnel.Session, error) {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for Dial")
	}

	var r0 tunnel.Session
	var r1 error
	if rf, ok := ret.Get(0).(func() (tunnel.Session, error)); ok {
		return rf()
	}
	if rf, ok := ret.Get(0).(func() tunnel.Session); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(tunnel.Session)
		}
	}

	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewSessionDialer creates a new instance of SessionDialer. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewSessionDialer(t interface {
	mock.TestingT
	Cleanup(func())
}) *SessionDialer {
	mock := &SessionDialer{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
