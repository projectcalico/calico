import LogDetailsView from '..';
import { render, screen, fireEvent } from '@/test-utils/helper';

const mockFlowlog = {
    start_time: 1698940029,
    end_time: 1698940352,
    source_ip: null,
    source_name: '-',
    source_name_aggr: 'prometheus-calico-node-prometheus-*',
    source_namespace: 'tigera-prometheus',
    nat_outgoing_ports: null,
    source_port: null,
    source_type: 'wep',
    source_labels: {
        labels: [
            'app.kubernetes.io/managed-by=prometheus-operator',
            'app.kubernetes.io/version=2.45.0',
            'app.kubernetes.io/instance=calico-node-prometheus',
            'app.kubernetes.io/name=prometheus',
            'statefulset.kubernetes.io/pod-name=prometheus-calico-node-prometheus-0',
            'prometheus=calico-node-prometheus',
            'controller-revision-hash=prometheus-calico-node-prometheus-858dcf7b65',
            'operator.prometheus.io/shard=0',
            'operator.prometheus.io/name=calico-node-prometheus',
        ],
    },
    dest_ip: null,
    dest_name: '-',
    dest_name_aggr: 'fluentd-node-*',
    dest_namespace: 'tigera-fluentd',
    dest_port: 9081,
    dest_type: 'wep',
    dest_labels: {
        labels: [
            'app.kubernetes.io/name=fluentd-node',
            'controller-revision-hash=7c887f95cb',
            'k8s-app=fluentd-node',
            'pod-template-generation=1',
        ],
    },
    dest_service_namespace: '-',
    dest_service_name: '-',
    dest_service_port: '-',
    dest_service_port_num: null,
    dest_domains: null,
};

const defaultProps = {
    logDocument: mockFlowlog,
};

describe('FlowLogDetails', () => {
    it('should render', () => {
        const { asFragment } = render(<LogDetailsView {...defaultProps} />);
        expect(asFragment()).toMatchSnapshot();
    });
    it('should render json', () => {
        const { asFragment } = render(<LogDetailsView {...defaultProps} />);
        fireEvent.click(
            screen.getByRole('tab', {
                name: /json/i,
            }),
        );
        expect(asFragment()).toMatchSnapshot();
    });
});
