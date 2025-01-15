module github.com/projectcalico/calico/lib/httpapimachinery

go 1.23.1

require (
	github.com/go-playground/form v3.1.4+incompatible
	github.com/google/uuid v1.6.0

	// TODO we may not want to import these (made a comment in the file that uses them). Ideally the library modules
	// TODO should be VERY light weight in it's dependencies to avoid dependency issues.
	// TODO IF we do include a muxer type here, then we should ensure that it is the muxer type that ALL apis use
	// TODO and they only import the use of that muxer from here (or we wrap it and hide the implementation). This way
	// TODO that importer won't have a direct dependency on the muxer, and it's indirect dependency should be updated
	// TODO when this module is updated.
	github.com/gorilla/mux v1.8.1
	github.com/sirupsen/logrus v1.9.3
)

require (
	github.com/go-playground/validator/v10 v10.22.1
	github.com/onsi/gomega v1.36.2
)

require (
	github.com/gabriel-vasile/mimetype v1.4.3 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/net v0.33.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
