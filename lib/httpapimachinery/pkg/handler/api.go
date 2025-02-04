package handler

import "net/http"

// API represents a method, url, and handler combination.
type API struct {
	Method     string
	URL        string
	Handler    handler
	Middleware []Middleware
}

type MiddlewareFunc func(http.Handler) http.Handler

func (mw MiddlewareFunc) Middleware(handler http.Handler) http.Handler {
	return mw(handler)
}

type Middleware interface {
	Middleware(handler http.Handler) http.Handler
}
