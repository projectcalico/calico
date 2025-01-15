# nfnetlink

Package that supports some features from some Netfilter netlink subsystems
* Conntrack (list/dump)
* NFLog (Subscribe to group)

### Example

Dump all conntrack entries to screen

```go
package main

import (
        "fmt"

        "github.com/tigera/nfnetlink"
)

type Handler struct {
        count int
}

func (h *Handler) HandleConntrackEntry(cte nfnetlink.CtEntry) {
        fmt.Printf("%+v\n", cte)
        h.count++
}

func ctdump() {
        handler := &Handler{}
        err := nfnetlink.ConntrackList(handler.HandleConntrackEntry)
        if err != nil {
                fmt.Println("Error: ", err)
        }
        fmt.Printf("Num entries returned %+v\n", handler.count)
}

func main() {
        fmt.Println("Running")
        ctdump()
}
```

Listen to a nflog-group and print received packet and metadata to screen

```go
package main

import (
	"fmt"

	"github.com/tigera/nfnetlink"
)

const GroupNum = 20

func nflog() {
	ch := make(chan nfnetlink.NflogPacket)
	done := make(chan struct{})
	defer close(done)
	err := nfnetlink.NflogSubscribe(GroupNum, ch, done)
	if err != nil {
		fmt.Println("Error: ", err)
	}
	for {
		nflogData := <-ch
		fmt.Printf("--- %+v\n", nflogData)
	}
}

func main() {
	fmt.Println("Running")
	nflog()
}
```
