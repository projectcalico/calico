import { render, screen } from '@/test-utils/helper';
import FlowLogsContainer from '..';

jest.mock('../../../api', () => ({
    useFlowLogs: jest.fn().mockReturnValue({}),
}));

jest.mock('../../FlowLogsList', () => () => 'Mock FlowLogsList');

jest.mock('../../../hooks', () => ({
    useFlowLogsHeightOffset: jest.fn().mockReturnValue(1),
}));

const defaultProps = {
    flowLogs: [],
    error: null,
    onRowClicked: jest.fn(),
    onSortClicked: jest.fn(),
    isFetching: false,
    maxStartTime: 0,
    totalItems: 0,
};

describe('FlowLogsContainer', () => {
    it('should render a loading skeleton', () => {
        render(<FlowLogsContainer {...defaultProps} isFetching={true} />);

        expect(
            screen.getByTestId('flow-logs-loading-skeleton'),
        ).toBeInTheDocument();
    });

    it('should render the flow logs list', () => {
        render(<FlowLogsContainer {...defaultProps} />);

        expect(screen.getByText('Mock FlowLogsList')).toBeInTheDocument();
    });
});
