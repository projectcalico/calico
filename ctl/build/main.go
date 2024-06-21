package main

import (
	"github.com/projectcalico/ctl/pkg/bootstrap"
)

const packageName = "github.com/projectcalico/ctl"

func main() {
	bootstrap.Main(packageName)
}
