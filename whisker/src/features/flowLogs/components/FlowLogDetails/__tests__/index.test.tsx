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

    it('should show the destination service as text', () => {
        render(
            <FlowLogDetails
                flowLog={{
                    ...flowLog,
                    service: {
                        name: 'kube-dns',
                        namespace: 'kube-system',
                        port: 53,
                        port_name: 'dns',
                    },
                }}
            />,
        );
        expect(screen.getByText('service')).toBeInTheDocument();
        expect(
            screen.getByText('kube-system/kube-dns:53 (dns)'),
        ).toBeInTheDocument();
    });

    it('should list the source and destination IPs', () => {
        render(
            <FlowLogDetails
                flowLog={{
                    ...flowLog,
                    source_ips: ['10.0.0.1', '10.0.0.2'],
                    dest_ips: ['10.96.0.10'],
                }}
            />,
        );

        expect(screen.getByText('source_ips')).toBeInTheDocument();
        expect(screen.getByText('dest_ips')).toBeInTheDocument();
        expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
        expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
        expect(screen.getByText('10.96.0.10')).toBeInTheDocument();
    });

    it('should leave out the IP rows when the flow has no IPs', () => {
        render(<FlowLogDetails flowLog={flowLog} />);

        expect(screen.queryByText('source_ips')).not.toBeInTheDocument();
        expect(screen.queryByText('dest_ips')).not.toBeInTheDocument();
    });
});
