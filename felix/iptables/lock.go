// Copyright (c) 2020 Tigera, Inc. All rights reserved.
// Copyright 2017 The Kubernetes Authors.
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

// This file is based on that extracted from Kubernetes at pkg/util/iptables/iptables_linux.go.

package iptables

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	cprometheus "github.com/projectcalico/calico/libcalico-go/lib/prometheus"
)

var (
	summaryLockAcquisitionTime = cprometheus.NewSummary(prometheus.SummaryOpts{
		Name: "felix_iptables_lock_acquire_secs",
		Help: "Time in seconds that it took to acquire the iptables lock(s).",
	})
	countLockRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "felix_iptables_lock_retries",
		Help: "Number of times the iptables lock was held by someone else and we had to retry.",
	}, []string{"version"})
	countLockRetriesV14 = countLockRetries.WithLabelValues("1.4")
	countLockRetriesV16 = countLockRetries.WithLabelValues("1.6")
)

func init() {
	prometheus.MustRegister(
		summaryLockAcquisitionTime,
		countLockRetries,
	)
}

func NewSharedLock(lockFilePath string, lockTimeout, lockProbeInterval time.Duration) *SharedLock {
	return &SharedLock{
		lockFilePath:      lockFilePath,
		lockTimeout:       lockTimeout,
		lockProbeInterval: lockProbeInterval,
		GrabIptablesLocks: GrabIptablesLocks,
	}
}

// SharedLock allows for multiple goroutines to share the iptables lock without blocking on each
// other.  That is safe because each of our goroutines is accessing a different iptables table, so
// they do not conflict.
type SharedLock struct {
	lock           sync.Mutex
	referenceCount int

	iptablesLockHandle io.Closer

	lockFilePath      string
	lockTimeout       time.Duration
	lockProbeInterval time.Duration

	GrabIptablesLocks func(lockFilePath, socketName string, timeout, probeInterval time.Duration) (io.Closer, error)
}

func (l *SharedLock) Lock() {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.referenceCount == 0 {
		// The lock isn't currently held.  Acquire it.
		lockHandle, err := l.GrabIptablesLocks(
			l.lockFilePath,
			"@xtables",
			l.lockTimeout,
			l.lockProbeInterval,
		)
		if err != nil {
			// We give the lock plenty of time so err on the side of assuming a
			// programming bug.
			log.WithError(err).Panic("Failed to acquire iptables lock")
		}
		l.iptablesLockHandle = lockHandle
	}
	l.referenceCount++
}

func (l *SharedLock) Unlock() {
	l.lock.Lock()
	defer l.lock.Unlock()

	l.referenceCount--
	if l.referenceCount < 0 {
		log.Panic("Unmatched Unlock()")
	}
	if l.referenceCount == 0 {
		log.Debug("Releasing iptables lock.")
		err := l.iptablesLockHandle.Close()
		if err != nil {
			// We haven't done anything with the file or socket so we shouldn't be
			// able to hit any "deferred flush" type errors from the close.  Panic
			// since we're not sure what's going on.
			log.WithError(err).Panic("Error while closing iptables lock.")
		}
		l.iptablesLockHandle = nil
	}
}

type Locker struct {
	Lock16 io.Closer
	Lock14 io.Closer
}

func (l *Locker) Close() error {
	var err error
	if l.Lock16 != nil {
		err = l.Lock16.Close()
		if err != nil {
			log.WithError(err).Error("Error while closing lock file.")
		}
	}
	if l.Lock14 != nil {
		err14 := l.Lock14.Close()
		if err14 != nil {
			log.WithError(err14).Error("Error while closing lock socket.")
		}
		if err14 != nil && err == nil {
			err = err14
		}
	}
	return err
}

var (
	Err14LockTimeout = errors.New("Timed out waiting for iptables 1.4 lock")
	Err16LockTimeout = errors.New("Timed out waiting for iptables 1.6 lock")
)

func GrabIptablesLocks(lockFilePath, socketName string, timeout, probeInterval time.Duration) (io.Closer, error) {
	var err error
	var success bool

	l := &Locker{}
	defer func(l *Locker) {
		// Clean up immediately on failure
		if !success {
			l.Close()
		}
	}(l)

	// Grab both 1.6.x and 1.4.x-style locks; we don't know what the
	// iptables-restore version is if it doesn't support --wait, so we
	// can't assume which lock method it'll use.

	// Roughly duplicate iptables 1.6.x xtables_lock() function.
	f, err := os.OpenFile(lockFilePath, os.O_CREATE, 0600)
	l.Lock16 = f
	if err != nil {
		return nil, fmt.Errorf("failed to open iptables lock %s: %v", lockFilePath, err)
	}

	startTime := time.Now()
	for {
		if err := grabIptablesFileLock(f); err == nil {
			break
		}
		if time.Since(startTime) > timeout {
			return nil, Err16LockTimeout
		}
		time.Sleep(probeInterval)
		countLockRetriesV16.Inc()
	}

	startTime14 := time.Now()
	for {
		l.Lock14, err = net.ListenUnix("unix", &net.UnixAddr{Name: socketName, Net: "unix"})
		if err == nil {
			break
		}
		if time.Since(startTime14) > timeout {
			return nil, Err14LockTimeout
		}
		time.Sleep(probeInterval)
		countLockRetriesV14.Inc()
	}

	summaryLockAcquisitionTime.Observe(time.Since(startTime).Seconds())

	success = true
	return l, nil
}

func grabIptablesFileLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
