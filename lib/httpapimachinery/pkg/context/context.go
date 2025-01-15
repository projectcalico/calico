// Copyright (c) 2023 Tigera, Inc. All rights reserved.

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
