module github.com/projectcalico/calico/lib/logrusr

go 1.26.4

require (
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.4
)

require golang.org/x/sys v0.47.0 // indirect

replace github.com/projectcalico/calico/lib/std => ../std
