package main

import (
	"fmt"
	"net/http"

	"github.com/projectcalico/calico/crypto/pkg/tls"
)

// This server is for testing purposes only to see if the tls config is affected by our build commands as expected.
func main() {
	server := http.Server{
		Addr:      ":8083",
		Handler:   fipsHandler{},
		TLSConfig: tls.NewTLSConfig(false),
	}

	err := server.ListenAndServeTLS("tmp/tls.crt", "tmp/tls.key")
	if err != nil {
		panic(err)
	}
}

type fipsHandler struct{}

func (h fipsHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(fmt.Sprintf("%t", tls.BuiltWithBoringCrypto)))
}
