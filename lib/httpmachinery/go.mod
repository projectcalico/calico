module github.com/projectcalico/calico/lib/httpmachinery

go 1.24.3

require (
	github.com/go-playground/form v3.1.4+incompatible
	github.com/go-playground/validator/v10 v10.26.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/onsi/gomega v1.36.2
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/snowzach/rotatefilehook v0.0.0-20220211133110-53752135082d // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/projectcalico/calico/lib/std => ../std
