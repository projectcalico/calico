package conntrack

import (
	"github.com/projectcalico/calico/felix/config"
	"reflect"
	"testing"
)

func TestConfigNames(t *testing.T) {
	c := config.New()
	to := DefaultTimeouts()
	v := reflect.ValueOf(&to)
	v = v.Elem()

	for key, _ := range c.BPFConntrackTimeouts {
		field := v.FieldByName(key)
		if !field.IsValid() {
			t.Errorf("Config contains invalid BPF conntrack timeout: %s", key)
			continue
		}
	}
	if v.NumField() != len(c.BPFConntrackTimeouts) {
		t.Errorf("Config is missing some timeouts")
	}
}
