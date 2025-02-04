import { FlowLog } from '@/types/api';
import FlowLogDetails from '..';
import { render, screen } from '@/test-utils/helper';

const flowLog: FlowLog = {
    start_time: new Date(),
    end_time: new Date(),
    action: 'allow',
    source_name: 'prometheus-calico-node-prometheus-0',
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
};

describe('FlowLogDetails', () => {
    it('should render the expected columns', () => {
        render(<FlowLogDetails flowLog={flowLog} />);

        expect(screen.getByText('start_time')).toBeInTheDocument();
        expect(screen.getByText('source_labels')).toBeInTheDocument();
    });
});
