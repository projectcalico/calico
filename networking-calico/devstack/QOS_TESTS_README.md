# QoS Responsiveness Tests for Calico OpenStack Integration

This directory contains additional functional verification (FV) tests that verify the responsiveness of Calico's integration code in converting QoS parameters from the Neutron API to the Calico WorkloadEndpoint API.

## Test Files

### qos_responsiveness_tests.py
Comprehensive QoS responsiveness test suite that:
- Creates various combinations of Network objects with and without `qos_policy_id` values
- Creates VMs with Network IDs and with/without per-VM `qos_policy_id` values  
- Creates QoS Policy and QoS Rule objects (bandwidth limits, packet rate limits)
- Verifies that corresponding WorkloadEndpoint objects are correctly updated within a few seconds
- Uses both etcd3 client and calicoctl for Calico datastore access

### simple_qos_test.py
Simplified QoS integration test that:
- Focuses on basic QoS policy creation and application
- Tests Neutron-side QoS configuration
- Provides basic connectivity verification with Calico
- Serves as a fallback when comprehensive tests cannot run

## Integration with DevStack

The tests are integrated into `bootstrap.sh` and run automatically after Tempest tests when `TEMPEST=true`. The integration:

1. First attempts to run the comprehensive test suite
2. Falls back to the simple test if the comprehensive test fails
3. Only fails the entire test run if both test suites fail
4. Automatically installs required dependencies (`openstacksdk`, `etcd3`)

## Test Scenarios

The tests cover the following QoS scenarios:

### Network-level QoS Policies
- Networks with QoS policies containing bandwidth limit rules
- Verification that ports created on these networks inherit the QoS settings

### Port-level QoS Policies  
- Ports with directly assigned QoS policies
- QoS policies with packet rate limit rules

### Mixed QoS Policies
- Networks with QoS policies and ports with different QoS policies
- Verification that port-level policies take precedence over network-level policies

### QoS Policy Updates
- Dynamic updates to existing QoS policies
- Adding new rules to existing policies
- Verification of responsiveness (updates within seconds)

### QoS Policy Removal
- Removing QoS policies from ports
- Verification that WorkloadEndpoint QoS controls are cleaned up

## QoS Rule Types Tested

### Bandwidth Limit Rules
- Ingress and egress bandwidth limits (max_kbps)
- Burst limits (max_burst_kbps)  
- Peak rate limits

### Packet Rate Limit Rules
- Ingress and egress packet rate limits (max_kpps)
- Packet burst limits

## Environment Variables

The tests use the following environment variables for configuration:

### OpenStack Connection
- `OS_AUTH_URL` (default: http://localhost/identity)
- `OS_PROJECT_NAME` (default: admin)  
- `OS_USERNAME` (default: admin)
- `OS_PASSWORD` (default: 015133ea2bdc46ed434c)
- `OS_REGION_NAME` (default: RegionOne)
- `OS_PROJECT_DOMAIN_ID` (default: default)
- `OS_USER_DOMAIN_ID` (default: default)

### Calico/etcd Connection
- `ETCD_HOST` (default: localhost)
- `ETCD_PORT` (default: 2379)

## Running Tests Manually

To run the tests manually in a DevStack environment:

```bash
# Set up OpenStack credentials
source /opt/stack/devstack/openrc admin admin

# Install dependencies
sudo pip install openstacksdk etcd3

# Run comprehensive tests
python3 qos_responsiveness_tests.py

# Or run simple tests
python3 simple_qos_test.py
```

## Expected Outcomes

### Success Criteria
- QoS policies can be created and applied to networks and ports
- WorkloadEndpoint objects are created/updated within reasonable time (< 10 seconds)
- QoS parameters are correctly converted from Neutron format to Calico format
- Policy updates and removals are processed responsively

### Integration Points Verified
- Neutron QoS plugin → Calico ML2 mechanism driver → Calico datastore
- QoS policy inheritance from networks to ports
- QoS policy precedence (port-level over network-level)
- Dynamic QoS policy updates

## Troubleshooting

### Common Issues

1. **etcd3 connection failures**: Tests fall back to calicoctl command line interface
2. **Missing QoS plugin**: Ensure Neutron QoS service plugin is enabled
3. **Permission issues**: Tests run as admin user to ensure full access to resources
4. **Timing issues**: Tests include configurable timeouts for responsiveness verification

### Debug Information

Tests provide detailed logging at INFO level, including:
- Resource creation and deletion
- QoS policy application status
- WorkloadEndpoint query results
- Timing information for responsiveness verification

## Contributing

When modifying these tests:

1. Ensure both comprehensive and simple tests remain functional
2. Add new test scenarios to verify additional QoS features
3. Maintain compatibility with different OpenStack versions
4. Update this documentation for new test scenarios