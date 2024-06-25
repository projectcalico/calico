package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

func main() {
	c := api.NewCalicoBuilder("apiserver")
	c.Register()
}
