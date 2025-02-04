package gorilla

import (
	"github.com/gorilla/mux"
	"net/http"

	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/server"
)

type Router interface {
	ServeHTTP(writer http.ResponseWriter, request *http.Request)
	Methods(methods ...string) Route
	Handle(string, http.Handler) Route
	Use(mwf ...handler.MiddlewareFunc)
}

type Route interface {
	Subrouter() Router
}

type router struct {
	router *mux.Router
}

func (g *router) RegisterAPIs(apis []handler.API, middlewares ...handler.MiddlewareFunc) http.Handler {
	midFuncs := make([]mux.MiddlewareFunc, len(middlewares))
	for i, m := range middlewares {
		midFuncs[i] = m.Middleware
	}
	for _, api := range apis {
		subRouter := g.router.Methods(api.Method).Subrouter()
		subRouter.Handle(api.URL, api.Handler)

		subRouter.Use(midFuncs...)

		for _, m := range api.Middleware {
			subRouter.Use(m.Middleware)
		}
	}

	return g.router
}

func NewRouter() server.Router {
	return &router{router: mux.NewRouter()}
}
