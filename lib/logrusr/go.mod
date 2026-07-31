module github.com/projectcalico/calico/lib/logrusr

go 1.26.5

require (
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.4
)

require (
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

replace github.com/projectcalico/calico/lib/std => ../std
