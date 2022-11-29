// Copyright (c) 2022 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package writelogger

import (
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

type WriteLogger struct {
	w io.Writer
}

func (wl *WriteLogger) Write(p []byte) (n int, err error) {
	logrus.WithField("len", len(p)).Debug("Writing...")
	start := time.Now()
	n, err = wl.w.Write(p)
	logrus.WithFields(logrus.Fields{
		"len":  len(p),
		"n":    n,
		"err":  err,
		"time": time.Since(start),
	}).Info("...write completed.")
	return
}

func New(w io.Writer) *WriteLogger {
	return &WriteLogger{w: w}
}

var _ io.Writer = (*WriteLogger)(nil)
