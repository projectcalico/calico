package main

import (
	"github.com/projectcalico/fixham/pkg/api"
)

func main() {
	c := api.NewBuilder()
	c.Register()
}
