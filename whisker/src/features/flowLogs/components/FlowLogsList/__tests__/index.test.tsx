import { FlowLog } from '@/types/api';
import FlowLogsList from '..';
import { fireEvent, render, screen } from '@/test-utils/helper';

jest.mock('../../FlowLogDetails', () => () => 'Mock FlowLogDetails');

const flowLogs: FlowLog[] = [
    {
        start_time: new Date(),
        end_time: new Date(),
        action: 'allow',
        source_name: 'fake-source-name',
        source_namespace: 'tigera-prometheus',
        source_labels:
            'app.kubernetes.io/version=2.54.1","prometheus=calico-node-prometheus","app.kubernetes.io/name=prometheus","statefulset.kubernetes.io/pod-name=prometheus-calico-node-prometheus-0","operator.prometheus.io/shard=0","app.kubernetes.io/instance=calico-node-prometheus","operator.prometheus.io/name=calico-node-prometheus","controller-revision-hash=prometheus-calico-node-prometheus-749869ffc6","apps.kubernetes.io/pod-index=0","app.kubernetes.io/managed-by=prometheus-operator","k8s-app=tigera-prometheus',
        dest_name: 'app.kubernetes.io/managed-by-tigera',
        dest_namespace: 'kube-system',
        dest_labels:
            'app.kubernetes.io/version=2.54.1","prometheus=calico-node-prometheus","app.kubernetes.io/name=prometheus","statefulset.kubernetes.io/pod-name=prometheus-calico-node-prometheus-0","operator.prometheus.io/shard=0","app.kubernetes.io/instance=calico-node-prometheus","operator.prometheus.io/name=calico-node-prometheus","controller-revision-hash=prometheus-calico-node-prometheus-749869ffc6","apps.kubernetes.io/pod-index=0","app.kubernetes.io/managed-by=prometheus-operator","k8s-app=tigera-prometheus',
        protocol: 'udp',
        dest_port: '53',
        reporter: 'src',
        packets_in: '6',
        packets_out: '6',
        bytes_in: '1286',
        bytes_out: '640',
    },
];

describe('FlowLogsList', () => {
    it('should render the expanded content', () => {
        render(<FlowLogsList flowLogs={flowLogs} />);

        fireEvent.click(screen.getByText('fake-source-name'));

        expect(screen.getByText('Mock FlowLogDetails')).toBeInTheDocument();
    });

    it('should render a loading skeleton', () => {
        render(<FlowLogsList isLoading={true} />);

        expect(
            screen.getByTestId('flow-logs-loading-skeleton'),
        ).toBeInTheDocument();
    });

    it('should render an error message', () => {
        render(<FlowLogsList error={{ data: {} }} />);

        expect(
            screen.getByText('Could not display any flow logs at this time'),
        ).toBeInTheDocument();
    });
});
