# projectcalico/api

This is canonical source for API definitions of Projectcalico.

## How to use

One way is to import the clientset directly and use it. See [examples/list-gnp/main.go](examples/list-gnp/main.go) for some example code.

## Adding new APIs
1. Create a .go file which contains the new type to `pkg/apis/<apigroup>/<version>`

1. Add the new type to `pkg/apis/<apigroup>/<version>/register.go`

1. Update generated code, including clients, informers, etc.

   ```
   make build
   ```
