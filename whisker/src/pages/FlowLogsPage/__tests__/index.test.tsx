import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import FlowLogsPage from '..';
import {
    useDeniedFlowLogsCount,
    useFlowLogsCount,
} from '@/features/flowLogs/api';
import { useStream } from '@/api';

jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    Outlet: ({ context }: any) => <>Flow logs view: {context.view}</>,
}));

jest.mock('@/features/flowLogs/api', () => ({
    useDeniedFlowLogsCount: jest.fn(),
    useFlowLogsCount: jest.fn(),
}));

jest.mock(
    '@/features/flowLogs/components/FlowLogsList',
    () => () => 'Mock FlowLogsList',
);

jest.mock('@/api', () => ({ useStream: jest.fn() }));

const useStreamStub = {
    stopStream: jest.fn(),
    startStream: jest.fn(),
    isStreaming: false,
    isFetching: false,
    data: [],
    error: null,
};

describe('FlowLogsPage', () => {
    it.skip('should render denied tabs info', () => {
        jest.mocked(useDeniedFlowLogsCount).mockReturnValue(101);
        jest.mocked(useFlowLogsCount).mockReturnValue(5);
        renderWithRouter(<FlowLogsPage />);

        expect(screen.getByTestId('denied-flows-tab')).toHaveTextContent(
            'Denied Flows',
        );
        expect(screen.getByTestId('denied-flows-tab')).toHaveTextContent('101');
        expect(screen.getByTestId('all-flows-tab')).toHaveTextContent(
            'All Flows',
        );
        expect(screen.getByTestId('all-flows-tab')).toHaveTextContent('5');
    });

    it('should render all flows context for the child', () => {
        jest.mocked(useStream).mockReturnValue(useStreamStub);
        jest.mocked(useDeniedFlowLogsCount).mockReturnValue(101);
        renderWithRouter(<FlowLogsPage />);

        expect(screen.getByText('Flow logs view: all')).toBeInTheDocument();
    });

    it('should render denied flows context for the child', () => {
        jest.mocked(useStream).mockReturnValue(useStreamStub);
        jest.mocked(useDeniedFlowLogsCount).mockReturnValue(101);
        renderWithRouter(<FlowLogsPage />, {
            routes: ['/denied-flows'],
        });

        expect(screen.getByText('Flow logs view: denied')).toBeInTheDocument();
    });

    it('should click play and call startStream', () => {
        const mockStartStream = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            ...useStreamStub,
            startStream: mockStartStream,
        });

        renderWithRouter(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Play' }));

        expect(mockStartStream).toHaveBeenCalled();
    });

    it('should click pause and call stopStream', () => {
        const mockStopStream = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            ...useStreamStub,
            stopStream: mockStopStream,
            isStreaming: true,
        });

        renderWithRouter(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

        expect(mockStopStream).toHaveBeenCalled();
    });
});
