import { render, screen } from '@/test-utils/helper';
import FlowLogsContainer from '..';
import { useOutletContext } from 'react-router-dom';
import { useFlowLogs } from '../../../api';
import FlowLogsList from '../../FlowLogsList';

jest.mock('react-router-dom', () => ({
    useOutletContext: jest.fn(),
}));

jest.mock('../../../api', () => ({
    useFlowLogs: jest.fn().mockReturnValue({}),
}));

jest.mock('../../FlowLogsList', () => jest.fn());

describe('FlowLogsContainer', () => {
    it.skip('should call useFlowLogs with denied query params', () => {
        jest.mocked(useOutletContext).mockReturnValue({ view: 'denied' });

        render(<FlowLogsContainer />);

        expect(useFlowLogs).toHaveBeenCalledWith({ action: 'deny' });
    });

    it.skip('should call useFlowLogs with no query params', () => {
        jest.mocked(useOutletContext).mockReturnValue({ view: 'all' });

        render(<FlowLogsContainer />);

        expect(useFlowLogs).toHaveBeenCalledWith(undefined);
    });

    it('should call useFlowLogs with denied query params', () => {
        jest.mocked(useOutletContext).mockReturnValue({
            view: 'denied',
            flowLogs: [],
            isLoading: false,
        });

        render(<FlowLogsContainer />);

        expect(FlowLogsList).toHaveBeenCalledWith(
            expect.objectContaining({
                error: undefined,
                flowLogs: [],
                isLoading: false,
            }),
            undefined,
        );
    });

    it('should render a loading skeleton', () => {
        jest.mocked(useOutletContext).mockReturnValue({
            isFetching: true,
        });

        render(<FlowLogsContainer />);

        expect(
            screen.getByTestId('flow-logs-loading-skeleton'),
        ).toBeInTheDocument();
    });
});
