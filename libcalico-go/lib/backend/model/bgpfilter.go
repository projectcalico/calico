package model

import (
	"fmt"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"reflect"
	"regexp"
)

var (
	matchBGPFilter = regexp.MustCompile("^/?calico/bgp/v1/filters/(.+)$")
)

type BGPFilterKey struct {
	Name string `json:"-" validate:"required,name"`
}

func (key BGPFilterKey) defaultPath() (string, error) {
	if key.Name == "" {
		return "", errors.ErrorInsufficientIdentifiers{Name: "name"}
	}
	e := fmt.Sprintf("/calico/bgp/v1/filters/%s", key.Name)
	return e, nil
}

func (key BGPFilterKey) defaultDeletePath() (string, error) {
	return key.defaultPath()
}

func (key BGPFilterKey) defaultDeleteParentPaths() ([]string, error) {
	return nil, nil
}

func (key BGPFilterKey) valueType() (reflect.Type, error) {
	return rawStringType, nil
}

func (key BGPFilterKey) String() string {
	return fmt.Sprintf("BGPFilter(name=%s)", key.Name)
}

type BGPFilterListOptions struct {
	Name string
}

func (options BGPFilterListOptions) defaultPathRoot() string {
	k := "/calico/bgp/v1/filters"
	if options.Name == "" {
		return k
	}
	k = k + fmt.Sprintf("/%s", options.Name)
	return k
}

func (options BGPFilterListOptions) KeyFromDefaultPath(path string) Key {
	log.Debugf("Get BGPFilter key from %s", path)
	r := matchBGPFilter.FindAllStringSubmatch(path, -1)
	if len(r) != 1 {
		log.Debugf("Didn't match BGPFilter regex")
		return nil
	}
	name := r[0][1]
	if options.Name != "" && name != options.Name {
		log.Debugf("Didn't match name for BGPFilter: %s != %s", options.Name, name)
		return nil
	}
	return BGPFilterKey{Name: name}
}
