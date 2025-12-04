package calico

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/projectcalico/calico/confd/pkg/backends/types"
)

func TestBGPConfig(t *testing.T) {
	// Test basic BGP configuration structure
	config := &types.BirdBGPConfig{
		NodeName:    "test-node",
		RouterID:    "192.168.1.1",
		AsNumber:    "64512",
		Peers:       []types.BirdBGPPeer{},
		Communities: []types.CommunityRule{},
		Filters:     map[string]string{},
	}

	// Test JSON serialization/deserialization
	jsonData, err := json.Marshal(config)
	assert.NoError(t, err)

	var deserializedConfig types.BirdBGPConfig
	err = json.Unmarshal(jsonData, &deserializedConfig)
	assert.NoError(t, err)
	assert.Equal(t, config.NodeName, deserializedConfig.NodeName)
	assert.Equal(t, config.RouterID, deserializedConfig.RouterID)
	assert.Equal(t, config.AsNumber, deserializedConfig.AsNumber)
}

func TestBGPPeer(t *testing.T) {
	// Test peer structure
	peer := types.BirdBGPPeer{
		Name:     "test-peer",
		IP:       "192.168.1.2",
		AsNumber: "65000",
		Type:     "external",
	}

	assert.Equal(t, "test-peer", peer.Name)
	assert.Equal(t, "192.168.1.2", peer.IP)
	assert.Equal(t, "65000", peer.AsNumber)
	assert.Equal(t, "external", peer.Type)
}

func TestCommunityRule(t *testing.T) {
	rule := types.CommunityRule{
		CIDR:          "10.0.0.0/8",
		AddStatements: []string{"bgp_community.add((65000, 100));"},
	}

	// Validate community rule structure
	assert.Equal(t, "10.0.0.0/8", rule.CIDR)
	assert.Equal(t, []string{"bgp_community.add((65000, 100));"}, rule.AddStatements)
}
