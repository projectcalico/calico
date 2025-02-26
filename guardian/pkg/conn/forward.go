// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package conn

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Forward sends all data coming from the srcConn to the dstConn, and all data coming from dstConn to srcConn. Both
// srcConn and dstConn are closed when this function returns
func Forward(srcConn net.Conn, dstCon net.Conn) {
	var wg sync.WaitGroup

	wg.Add(2)
	go forwardConnection(srcConn, dstCon, &wg)
	go forwardConnection(dstCon, srcConn, &wg)

	wg.Wait()
}

// forwardConnection forwards data from srcConn to dstConn. This function attempts to close both srcConn and dstConn, and
// ignores all "use of closed network connection" errors, as these errors are benign.
func forwardConnection(srcConn net.Conn, dstCon net.Conn, wg *sync.WaitGroup) {
	defer func() {
		if err := srcConn.Close(); err != nil && !isUseOfClosedNetworkErr(err) {
			logrus.WithError(err).Error("failed to close src connection")
		}
	}()
	defer func() {
		if err := dstCon.Close(); err != nil && !isUseOfClosedNetworkErr(err) {
			logrus.WithError(err).Error("failed to close dst connection")
		}
	}()
	defer wg.Done()

	if _, err := io.Copy(dstCon, srcConn); err != nil && !isUseOfClosedNetworkErr(err) {
		logrus.WithError(err).Error("failed to forward data")
	}
}

func isUseOfClosedNetworkErr(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	switch err := err.(type) {
	case *net.OpError:
		if strings.Contains(err.Err.Error(), "use of closed network connection") {
			return true
		}
	}
	return false
}
