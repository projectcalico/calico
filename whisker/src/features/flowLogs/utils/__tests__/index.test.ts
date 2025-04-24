import { FlowLog } from '@/types/render';
import { handleDuplicateFlowLogs } from '..';

const createFlowLog = (
    startTime: Date,
    name: string = 'fake-source-name',
): FlowLog => ({
    id: '1',
    start_time: startTime,
    end_time: new Date(),
    action: 'Allow',
    source_name: name,
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
});

describe('utils', () => {
    describe('handleDuplicateFlowLogs', () => {
        it('should return null when a flow already exists', () => {
            const flowLog = createFlowLog(new Date(0));
            const flowLogs = [
                {
                    flowLog,
                    json: JSON.stringify({ ...flowLog, id: undefined }),
                },
            ];
            const startTime = new Date(0).getTime();

            const result = handleDuplicateFlowLogs({
                flowLog,
                startTime,
                flowLogs,
            });

            expect(result).toEqual({
                flowLog: null,
                flowLogs,
                startTime,
            });
        });

        it('should return a new response when a the start time is different', () => {
            const flowLog = createFlowLog(new Date(1));
            const oldFlowLog = createFlowLog(new Date(0));
            const flowLogs = [
                {
                    flowLog: oldFlowLog,
                    json: JSON.stringify({ ...oldFlowLog, id: undefined }),
                },
                {
                    flowLog: oldFlowLog,
                    json: JSON.stringify({ ...oldFlowLog, id: undefined }),
                },
            ];
            const startTime = new Date(0).getTime();

            const result = handleDuplicateFlowLogs({
                flowLog,
                startTime,
                flowLogs,
            });

            expect(result).toEqual({
                flowLog,
                flowLogs: [
                    {
                        flowLog,
                        json: JSON.stringify({ ...flowLog, id: undefined }),
                    },
                ],
                startTime: flowLog.start_time.getTime(),
            });
        });

        it('should add the flow log to the existing list', () => {
            const flowLog = createFlowLog(new Date(0), 'new-flow');
            const oldFlowLog = createFlowLog(new Date(0));
            const flowLogs = [
                {
                    flowLog: oldFlowLog,
                    json: JSON.stringify({ ...oldFlowLog, id: undefined }),
                },
            ];
            const startTime = new Date(0).getTime();

            const result = handleDuplicateFlowLogs({
                flowLog,
                startTime,
                flowLogs,
            });

            expect(result).toEqual({
                flowLog,
                flowLogs: [
                    ...flowLogs,
                    {
                        flowLog,
                        json: JSON.stringify({ ...flowLog, id: undefined }),
                    },
                ],
                startTime,
            });
        });
    });
});
