package bootstrap

import (
	"github.com/goyek/goyek/v2"

	"github.com/projectcalico/fixham/pkg/ctl"
)

// Lint is a goyek task that runs the linter using golangci-lint.
var Lint = goyek.Define(goyek.Task{
	Name:  "golangci-lint",
	Usage: "Run linter",
	Action: func(a *goyek.A) {
		a.Log("Running linter")
		ctl.NewClient(*packageName).Lint()
	},
	Parallel: true,
})

// Fmt is a goyek task that checks code formatting using goimports.
var Fmt = goyek.Define(goyek.Task{
	Name:  "check-fmt",
	Usage: "Check code formatting",
	Action: func(a *goyek.A) {
		a.Log("Checking code formatting.  Any listed files don't match goimports:")
		ctl.NewClient(*packageName).CheckFmt()
	},
	Parallel: true,
})

// FixFmt is a goyek task that fixes code formatting using goimports.
var FixFmt = goyek.Define(goyek.Task{
	Name:  "fix-fmt",
	Usage: "Fix code formatting",
	Action: func(a *goyek.A) {
		ctl.NewClient(*packageName).FixFmt()
	},
})

// StaticChecks is a goyek task that runs the linter and checks code formatting.
var StaticChecks = goyek.Define(goyek.Task{
	Name:  "static-checks",
	Usage: "Run linter and check formatting",
	Deps:  []*goyek.DefinedTask{Lint, Fmt},
})
