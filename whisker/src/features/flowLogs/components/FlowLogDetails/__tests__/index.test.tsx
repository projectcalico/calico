import { FlowLog } from '@/types/render';
import FlowLogDetails from '..';
import { render, screen } from '@/test-utils/helper';

const flowLog: FlowLog = {
    id: '1',
    start_time: new Date(),
    end_time: new Date(),
    action: 'Allow',
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
    policies: {
        enforced: [
            {
                kind: '',
                name: '',
                namespace: '',
                tier: '',
                action: '',
                policy_index: 0,
                rule_index: 0,
                trigger: null,
            },
        ],
        pending: [
            {
                kind: '',
                name: '',
                namespace: '',
                tier: '',
                action: '',
                policy_index: 0,
                rule_index: 0,
                trigger: null,
            },
        ],
    },
};

describe('FlowLogDetails', () => {
    it('should render the expected columns', () => {
        render(<FlowLogDetails flowLog={flowLog} />);

        expect(screen.getByText('start_time')).toBeInTheDocument();
        expect(screen.getByText('source_labels')).toBeInTheDocument();
    });
});
