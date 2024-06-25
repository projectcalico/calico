package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

// APIServer is a struct that represents APIServer
type APIServer struct {
	api.CalicoComponent
}

func main() {
	c := api.NewCalicoComponent("apiserver")
	c.Register()
}
