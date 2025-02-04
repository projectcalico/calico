package main

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/handler"

	"github.com/projectcalico/calico/lib/httpapimachinery/pkg/server"
	gorillaadpt "github.com/projectcalico/calico/lib/httpapimachinery/pkg/server/adaptors/gorilla"
)

func main() {
	apis := []handler.API{
		{},
	}

	srv, err := server.NewHTTPServer(gorillaadpt.NewRouter(mux.NewRouter()), apis)
	if err != nil {
		panic(err)
	}

	if err := srv.ListenAndServeTLS(context.Background()); err != nil {
		panic(err)
	}
}
