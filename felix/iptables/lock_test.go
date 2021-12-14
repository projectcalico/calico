// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

package iptables_test

import (
	"io"
	"io/ioutil"
	"os"
	"time"

	. "github.com/projectcalico/felix/iptables"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SharedLock", func() {
	var lock *SharedLock
	var mockIptablesLock *mockLock
	var mockErr error

	mockGrabLock := func(lockFilePath, socketName string, timeout, probeInterval time.Duration) (io.Closer, error) {
		return mockIptablesLock, mockErr
	}

	BeforeEach(func() {
		mockErr = nil
		mockIptablesLock = &mockLock{}
		lock = NewSharedLock("/foo/bar.lock", time.Second, time.Millisecond)
		lock.GrabIptablesLocks = mockGrabLock
	})

	It("should close the lock after final unlock call", func() {
		lock.Lock()
		Expect(mockIptablesLock.Closed).To(BeFalse())
		lock.Unlock()
		Expect(mockIptablesLock.Closed).To(BeTrue())
	})
	It("should allow multiple holders", func() {
		lock.Lock()
		lock.Lock()
		Expect(mockIptablesLock.Closed).To(BeFalse())
		lock.Unlock()
		Expect(mockIptablesLock.Closed).To(BeFalse())
		lock.Unlock()
		Expect(mockIptablesLock.Closed).To(BeTrue())
	})
	It("should panic on misuse", func() {
		Expect(lock.Unlock).To(Panic())
	})
	It("should panic on failure to acquire", func() {
		mockErr = Err14LockTimeout
		Expect(lock.Lock).To(Panic())
	})
	It("should panic on failure to close", func() {
		lock.Lock()
		mockIptablesLock.Err = Err14LockTimeout
		Expect(lock.Unlock).To(Panic())
	})
})

type mockLock struct {
	Closed bool
	Err    error
}

func (l *mockLock) Close() error {
	Expect(l.Closed).To(BeFalse())
	l.Closed = true
	return l.Err
}

var _ = Describe("GrabIptablesLocks FV", func() {
	var fileName string

	BeforeEach(func() {
		f, err := ioutil.TempFile("", "iptlocktest")
		Expect(err).NotTo(HaveOccurred())
		fileName = f.Name()
		f.Close()
	})
	AfterEach(func() {
		os.Remove(fileName)
	})

	It("should block concurrent invocations", func() {
		l, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()

		l2, err := GrabIptablesLocks(fileName, "@dummytables", 100*time.Millisecond, 10*time.Millisecond)
		Expect(err).To(Equal(Err16LockTimeout))
		Expect(l2).To(BeNil())
	})
	It("should allow access after being released", func() {
		l, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		l.Close()

		l2, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		l2.Close()
	})
	It("should block concurrent invocations using only iptables 1.4 version of lock", func() {
		l, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		// Sneakily remove the lockfile after it's been locked so that we fall through to
		// the v1.4 lock.
		os.Remove(fileName)
		Expect(err).NotTo(HaveOccurred())
		defer l.Close()

		l2, err := GrabIptablesLocks(fileName, "@dummytables", 100*time.Millisecond, 10*time.Millisecond)
		Expect(err).To(Equal(Err14LockTimeout))
		Expect(l2).To(BeNil())
	})
	It("should allow access after being released using only iptables 1.4 version of lock", func() {
		l, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		// Sneakily remove the lockfile after it's been locked so that we fall through to
		// the v1.4 lock.
		os.Remove(fileName)
		Expect(err).NotTo(HaveOccurred())
		l.Close()

		l2, err := GrabIptablesLocks(fileName, "@dummytables", 1*time.Second, 50*time.Millisecond)
		Expect(err).NotTo(HaveOccurred())
		l2.Close()
	})
})

var _ = Describe("locker", func() {
	var l *Locker
	var lock14 mockCloser
	var lock16 mockCloser

	BeforeEach(func() {
		lock14 = mockCloser{}
		lock16 = mockCloser{}
		l = &Locker{
			Lock14: &lock14,
			Lock16: &lock16,
		}
	})

	It("should return nil with no err", func() {
		Expect(l.Close()).NotTo(HaveOccurred())
	})
	It("should return lock16 err", func() {
		lock16.Err = Err16LockTimeout
		Expect(l.Close()).To(Equal(Err16LockTimeout))
	})
	It("should return lock14 err", func() {
		lock14.Err = Err14LockTimeout
		Expect(l.Close()).To(Equal(Err14LockTimeout))
	})
})

type mockCloser struct {
	Err error
}

func (c *mockCloser) Close() error {
	return c.Err
}
