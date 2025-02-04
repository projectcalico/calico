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

package context

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/google/uuid"

	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/header"
)

// Key is used to ensure we don't have collisions with existing keys.
type Key string

const (
	ctxRequestIdKey Key = "requestId"
	ctxLoggerKey    Key = "logger"
)

type Context interface {
	context.Context
	Logger() *logrus.Entry
	RequestID() string
}

type requestContext struct {
	context.Context
}

func NewRequestContext(req *http.Request) Context {
	requestID := req.Header.Get(header.XRequestId)
	if requestID == "" {
		requestID = uuid.New().String()
	}

	logger := logrus.NewEntry(logrus.StandardLogger())
	logger = logger.WithField("requestID", requestID)

	ctx := context.WithValue(req.Context(), ctxRequestIdKey, requestID)
	ctx = context.WithValue(ctx, ctxLoggerKey, logger)

	return &requestContext{Context: ctx}
}

func (ctx *requestContext) Logger() *logrus.Entry {
	// We don't validate the type since it should be impossible to get a requestContext without this set properly. If
	// it's not set, we want to panic since this is a developer error.
	return ctx.Value(ctxLoggerKey).(*logrus.Entry)
}

func (ctx *requestContext) RequestID() string {
	// We don't validate the type since it should be impossible to get a requestContext without this set properly. If
	//	// it's not set, we want to panic since this is a developer error.
	return ctx.Context.Value(ctxRequestIdKey).(string)
}
