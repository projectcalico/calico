module github.com/projectcalico/calico/lib/log

go 1.23.7

require (
	github.com/projectcalico/calico/lib/std v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
)

require golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect

replace github.com/projectcalico/calico/lib/std => ../std
