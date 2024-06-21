package main

import (
	"github.com/projectcalico/ctl/pkg/bootstrap"
)

const packageName = "github.com/projectcalico/ctl"

var _ = bootstrap.DefineCleanTask([]string{"./bin/*"}, nil, nil)

func main() {
	bootstrap.Main(packageName)
}
