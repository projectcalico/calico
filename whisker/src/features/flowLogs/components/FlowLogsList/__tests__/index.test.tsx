import { FlowLog } from '@/types/render';
import FlowLogsList from '..';
import { fireEvent, render, screen, within } from '@/test-utils/helper';

jest.mock('../../FlowLogDetails', () => () => 'Mock FlowLogDetails');

const flowLogs: FlowLog[] = [
    {
        id: '1',
        start_time: new Date('2025-01-01T10:00:00Z'),
        end_time: new Date('2025-01-01T10:05:00Z'),
        action: 'Allow',
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
    },
];

const secondFlowLog: FlowLog = {
    ...flowLogs[0],
    id: '2',
    start_time: new Date('2025-01-01T11:00:00Z'),
    end_time: new Date('2025-01-01T11:05:00Z'),
    source_name: 'other-source-name',
};

const defaultProps = {
    onRowClicked: jest.fn(),
    onSortClicked: jest.fn(),
    maxStartTime: 0,
    flowLogs: [],
    heightOffset: 0,
    totalItems: 0,
    hasActiveFilters: false,
};

const openColumnCustomizer = () => {
    const columnHeaders = screen.getAllByTestId('column-header');
    const [customizerButton] = within(
        columnHeaders[columnHeaders.length - 1],
    ).getAllByRole('button');
    fireEvent.click(customizerButton);
};

describe('FlowLogsList', () => {
    beforeEach(() => {
        window.localStorage.clear();
        jest.clearAllMocks();
    });

    it('should render the expanded content', () => {
        render(<FlowLogsList {...defaultProps} flowLogs={flowLogs} />);

        fireEvent.click(screen.getByText('fake-source-name'));

        expect(screen.getByText('Mock FlowLogDetails')).toBeInTheDocument();
    });

    it('should render a loading skeleton', () => {
        render(<FlowLogsList isLoading={true} {...defaultProps} />);

        expect(
            screen.getByTestId('flow-logs-loading-skeleton'),
        ).toBeInTheDocument();
    });

    it('should render an error message', () => {
        render(<FlowLogsList error={{ data: {} }} {...defaultProps} />);

        expect(
            screen.getByText('Could not display any flow logs at this time'),
        ).toBeInTheDocument();
    });

    it('should render an empty table when flowLogs is undefined', () => {
        render(
            <FlowLogsList
                {...defaultProps}
                flowLogs={undefined as unknown as FlowLog[]}
            />,
        );

        expect(screen.getByText('Nothing to see yet.')).toBeInTheDocument();
        expect(screen.queryByText('fake-source-name')).not.toBeInTheDocument();
    });

    it('should hide a column after unchecking it in the column customizer', () => {
        render(<FlowLogsList {...defaultProps} flowLogs={flowLogs} />);

        expect(screen.getByText('dest_port')).toBeInTheDocument();

        openColumnCustomizer();

        const modalBody = screen.getByTestId(
            'reorderable-checklist-modal-body',
        );
        fireEvent.click(within(modalBody).getByText('dest_port'));
        fireEvent.click(screen.getByRole('button', { name: 'Save' }));

        expect(screen.queryByText('dest_port')).not.toBeInTheDocument();
        expect(
            JSON.parse(
                window.localStorage.getItem(
                    'whisker-flow-logs-stream-columns-v2',
                ) ?? '{}',
            ),
        ).toEqual(
            expect.objectContaining({
                dest_port: false,
                source_name: true,
            }),
        );
    });

    it('should close the column customizer on cancel without changing columns', () => {
        render(<FlowLogsList {...defaultProps} flowLogs={flowLogs} />);

        openColumnCustomizer();

        expect(
            screen.getByTestId('reorderable-checklist-modal-body'),
        ).toBeInTheDocument();

        fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

        expect(
            screen.queryByTestId('reorderable-checklist-modal-body'),
        ).not.toBeInTheDocument();
        expect(screen.getByText('dest_port')).toBeInTheDocument();
    });

    it('should sort rows when clicking sortable column headers', () => {
        render(
            <FlowLogsList
                {...defaultProps}
                flowLogs={[...flowLogs, secondFlowLog]}
                totalItems={2}
            />,
        );

        const renderedSourceNames = () =>
            screen
                .getAllByText(/source-name/)
                .map((element) => element.textContent);

        // default sort is start_time desc, the newest flow log renders first
        expect(renderedSourceNames()).toEqual([
            'other-source-name',
            'fake-source-name',
        ]);

        // sorting by start_time asc flips the order
        fireEvent.click(screen.getByText('start_time'));
        expect(defaultProps.onSortClicked).toHaveBeenCalledTimes(1);
        expect(renderedSourceNames()).toEqual([
            'fake-source-name',
            'other-source-name',
        ]);

        // sorting by end_time exercises its custom sort function
        fireEvent.click(screen.getByText('end_time'));
        expect(defaultProps.onSortClicked).toHaveBeenCalledTimes(2);
    });
});
