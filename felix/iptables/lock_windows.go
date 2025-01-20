// Copyright (c) 2018-2025 Tigera, Inc. All rights reserved.

package iptables

import "sync"

func NewSharedLock() {
	panic("iptables lock is not implemented for windows platform")
}

// SharedLock allows for multiple goroutines to share the iptables lock without blocking on each
// other.  That is safe because each of our goroutines is accessing a different iptables table, so
// they do not conflict.
// This is just a stub placeholder for windows
type SharedLock struct {
	lock sync.Mutex
}

func (l *SharedLock) Lock() {
	l.lock.Lock()
	defer l.lock.Unlock()

}

func (l *SharedLock) Unlock() {
	l.lock.Lock()
	defer l.lock.Unlock()

}
