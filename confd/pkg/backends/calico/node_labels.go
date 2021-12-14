package calico

import (
	"reflect"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/calico/libcalico-go/lib/selector"
)

// newNodeLabelManager returns a newly initialized nodeLabelManager with no label data.
func newNodeLabelManager() nodeLabelManager {
	return nodeLabelManager{
		nodeLabels: map[string]map[string]string{},
	}
}

// nodeLabelManager is a helper structure for interacting with node labels.
// It ensures concurrent access of a centralized label cache is safe.
type nodeLabelManager struct {
	sync.Mutex

	// Map of nodename to labels for that node.
	nodeLabels map[string]map[string]string
}

func (m *nodeLabelManager) labelsForNode(n string) (map[string]string, bool) {
	m.Lock()
	defer m.Unlock()
	l, ok := m.nodeLabels[n]

	// Make a copy of the labels map.
	labels := make(map[string]string, len(l))
	for k, v := range l {
		labels[k] = v
	}
	return labels, ok
}

func (m *nodeLabelManager) nodeExists(n string) bool {
	m.Lock()
	defer m.Unlock()
	_, ok := m.nodeLabels[n]
	return ok
}

func (m *nodeLabelManager) setLabels(n string, l map[string]string) bool {
	m.Lock()
	defer m.Unlock()
	existingLabels, ok := m.nodeLabels[n]
	changed := !ok || !reflect.DeepEqual(existingLabels, l)
	m.nodeLabels[n] = l
	return changed
}

func (m *nodeLabelManager) deleteNode(n string) {
	m.Lock()
	defer m.Unlock()
	delete(m.nodeLabels, n)
}

func (m *nodeLabelManager) nodesMatching(rawSelector string) []string {
	m.Lock()
	defer m.Unlock()

	nodeNames := []string{}
	sel, err := selector.Parse(rawSelector)
	if err != nil {
		log.Errorf("Couldn't parse selector: %v", rawSelector)
		return nodeNames
	}
	for nodeName, labels := range m.nodeLabels {
		if sel.Evaluate(labels) {
			nodeNames = append(nodeNames, nodeName)
		}
	}
	return nodeNames
}

func (m *nodeLabelManager) listNodes() []string {
	m.Lock()
	defer m.Unlock()

	nodes := []string{}
	for n := range m.nodeLabels {
		nodes = append(nodes, n)
	}
	return nodes
}
