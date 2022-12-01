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

package readlogger

import (
	"io"
	"time"

	"github.com/sirupsen/logrus"
)

type ReadLogger struct {
	r io.Reader
}

func (wl *ReadLogger) Read(p []byte) (n int, err error) {
	logrus.WithField("len", len(p)).Debug("Reading...")
	start := time.Now()
	n, err = wl.r.Read(p)
	logrus.WithFields(logrus.Fields{
		"len":  len(p),
		"n":    n,
		"err":  err,
		"time": time.Since(start),
	}).Info("...read completed.")
	return
}

func New(r io.Reader) *ReadLogger {
	return &ReadLogger{r: r}
}

var _ io.Reader = (*ReadLogger)(nil)
