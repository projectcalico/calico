package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

// APIServerBuilder is a struct that represents APIServerBuilder
type APIServerBuilder struct {
	api.CalicoBuilder
}

func main() {
	c := api.NewCalicoBuilder("apiserver")
	c.Register()
}
