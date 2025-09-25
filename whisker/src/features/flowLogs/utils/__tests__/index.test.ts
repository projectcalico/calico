import { FlowLog } from '@/types/render';
import { handleDuplicateFlowLogs, getV1Columns, getV2Columns } from '..';

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

    describe('getV1Columns', () => {
        const mockLocalStorage = {
            removeItem: jest.fn(),
            setItem: jest.fn(),
        };

        beforeEach(() => {
            Object.defineProperty(window, 'localStorage', {
                value: mockLocalStorage,
                writable: true,
            });
            jest.clearAllMocks();
        });

        it('should handle empty v1StoredColumns string', () => {
            const result = getV1Columns('');

            expect(result).toEqual({
                start_time: false,
                end_time: false,
                action: false,
                source_namespace: false,
                source_name: false,
                dest_namespace: false,
                dest_name: false,
                protocol: false,
                dest_port: false,
                reporter: true,
            });
            expect(mockLocalStorage.removeItem).toHaveBeenCalledWith(
                'whisker-flow-logs-stream-columns',
            );
        });

        it('should set specified columns to true when v1StoredColumns contains valid column names', () => {
            const v1Columns = ['start_time', 'action', 'protocol'];
            const result = getV1Columns(JSON.stringify(v1Columns));

            expect(result).toEqual({
                start_time: true,
                end_time: false,
                action: true,
                source_namespace: false,
                source_name: false,
                dest_namespace: false,
                dest_name: false,
                protocol: true,
                dest_port: false,
                reporter: true,
            });

            expect(mockLocalStorage.removeItem).toHaveBeenCalledWith(
                'whisker-flow-logs-stream-columns',
            );
        });

        it('should handle empty array in v1StoredColumns', () => {
            const result = getV1Columns(JSON.stringify([]));

            expect(result).toMatchObject({
                reporter: true,
            });
        });
    });

    describe('getV2Columns', () => {
        const mockLocalStorage = {
            removeItem: jest.fn(),
            setItem: jest.fn(),
        };

        beforeEach(() => {
            Object.defineProperty(window, 'localStorage', {
                value: mockLocalStorage,
                writable: true,
            });
            jest.clearAllMocks();
        });

        it('should add new columns', () => {
            const storedString = JSON.stringify({
                start_time: true,
                end_time: false,
            });

            const result = getV2Columns(storedString, 'test-key', {
                start_time: true,
                end_time: true,
                reporter: true,
            } as any);

            const expected = {
                start_time: true,
                end_time: false,
                reporter: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });

        it('should remove old columns', () => {
            const storedString = JSON.stringify({
                start_time: true,
                end_time: true,
            });

            const result = getV2Columns(storedString, 'test-key', {
                start_time: true,
            } as any);

            const expected = {
                start_time: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });

        it('should use the initial value when there is no stored string', () => {
            const result = getV2Columns('', 'test-key', {
                start_time: true,
            } as any);

            const expected = {
                start_time: true,
            };
            expect(result).toEqual(expected);
            expect(mockLocalStorage.setItem).toHaveBeenCalledWith(
                'test-key',
                JSON.stringify(expected),
            );
        });
    });
});
