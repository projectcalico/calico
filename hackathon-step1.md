# Building a Custom calicoctl Subcommand: Hello World

This example walks through extending calicoctl by adding a custom `hackathon` subcommand that prints "Hello world!"—a minimal example that demonstrates how to plug into the calicoctl CLI.

## The Idea

Calico is a powerful open-source networking and security solution for Kubernetes, composed of many components.

calicoctl is the command-line utility that lets users interact with Calico’s custom resources. It ships with many built-in commands (create, get, node, ipam, etc.), but you may want to add your own functionality—whether for a hackathon, internal tooling, or experimentation.

Adding a custom subcommand is straightforward: calicoctl uses a simple switch-based dispatcher. Each command is a function that receives `args []string` and returns `error`. By creating a new command file and registering it in the main binary, you can extend calicoctl without modifying its core logic.

## How We Achieved It

We built `calicoctl hackathon` in two steps.

### Step 1: Create the command handler

We added `calicoctl/calicoctl/commands/hackathon.go` with a minimal handler:

```go
package commands

import "fmt"

func Hackathon(args []string) error {
	fmt.Println("Hello world!")
	return nil
}
```

The function signature `Hackathon(args []string) error` matches the pattern used by all other calicoctl commands. We keep it minimal: no docopt, no flags—just print and return.

### Step 2: Register in the main binary

We updated `calicoctl/calicoctl/calicoctl.go` in two places:

1. **Usage doc** — Add a line so `calicoctl --help` lists the new command:
   ```
   hackathon    Hello world from Calico.
   ```

2. **Switch case** — Add a branch so the dispatcher routes `hackathon` to our handler:
   ```go
   case "hackathon":
       err = commands.Hackathon(args)
   ```

The main function parses the CLI with docopt, extracts the command name, and passes the full args slice to the appropriate handler. Our new case fits right in.

## How to build calico componenents

To build Calico take a look at [build](./DEVELOPER_GUIDE.md)

## Gotchas

- **Exported vs. command name**: In Go, the function must be exported (`Hackathon`) so it can be called from the `main` package. The command string users type is lowercase (`hackathon`). Don't confuse the two.

- **Doc placement**: The usage doc and switch case must stay in sync. If you add a command to one but not the other, users will either see it in `--help` but get "unknown command", or vice versa.

- **Args propagation**: The `args` slice includes the command name as the first element (e.g. `["hackathon"]`). For more complex commands, you'll typically parse this with docopt or a similar library.

## Adding Your Own Functionality

To add another subcommand:

1. Create `commands/yourcommand.go` with `func YourCommand(args []string) error`.
2. Add a line to the usage doc in `calicoctl.go`.
3. Add a `case "yourcommand": err = commands.YourCommand(args)` in the switch.

To extend `hackathon` itself, you can add docopt for flags, call Calico client APIs (e.g. via `clientmgr`), or add sub-subcommands—following the patterns used by `cluster`, `node`, or `ipam`.

## What's Next

This hello world is just the beginning. Calico offers rich APIs for network policy, IPAM, BGP, and more. To dive deeper:

- **[docs.tigera.io](https://docs.tigera.io)** — Official Calico documentation, tutorials, and reference
- **[Calico GitHub](https://github.com/projectcalico/calico)** — Source code and contribution guides

Happy hacking!
