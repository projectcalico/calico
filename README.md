[![Build Status](https://semaphoreci.com/api/v1/calico/confd/branches/master/shields_badge.svg)](https://semaphoreci.com/calico/confd) [![Slack Status](https://slack.projectcalico.org/badge.svg)](https://slack.projectcalico.org) [![IRC Channel](https://img.shields.io/badge/irc-%23calico-blue.svg)](https://kiwiirc.com/client/irc.freenode.net/#calico) [![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](http://godoc.org/github.com/projectcalico/confd)

# confd

This is a Calico-specific version of confd.  It is heavily modified from the original and only
supports a single backend type - namely a Calico datastore.  It has a single purpose which is
to monitor Calico BGP configuration and to autogenerate bird BGP templates from that config.

For details on the original implementation, see:

https://github.com/kelseyhightower/confd.git
