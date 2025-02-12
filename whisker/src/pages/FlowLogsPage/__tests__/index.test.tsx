import { useStream } from '@/api';
import {
    useDeniedFlowLogsCount,
    useFlowLogsCount,
} from '@/features/flowLogs/api';
import { useOmniFilterUrlState } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import FlowLogsPage from '..';

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

jest.mock('@/libs/tigera/ui-components/components/common/OmniFilter', () => ({
    ...jest.requireActual(
        '@/libs/tigera/ui-components/components/common/OmniFilter',
    ),
    useOmniFilterUrlState: jest.fn().mockReturnValue([]),
}));

const MockOmniFilters = {
    onReset: jest.fn(),
    onChange: jest.fn(),
};

jest.mock(
    '@/features/flowLogs/components/OmniFilters',
    () =>
        ({ onReset, onChange }: any) => {
            MockOmniFilters.onReset = onReset;
            MockOmniFilters.onChange = onChange;
            return <>MockOmniFilters</>;
        },
);

jest.mock('@/hooks', () => ({ useSelectedOmniFilters: jest.fn() }));

const useStreamStub = {
    stopStream: jest.fn(),
    startStream: jest.fn(),
    isStreaming: false,
    isFetching: false,
    data: [],
    error: null,
};

describe('FlowLogsPage', () => {
    beforeEach(() => {
        jest.mocked(useStream).mockReturnValue(useStreamStub);
    });
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
        jest.mocked(useDeniedFlowLogsCount).mockReturnValue(101);
        renderWithRouter(<FlowLogsPage />);

        expect(screen.getByText('Flow logs view: all')).toBeInTheDocument();
    });

    it('should render denied flows context for the child', () => {
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

    it('should test <OmniFilters /> clears filter params', () => {
        const mockClearFilterParams = jest.fn();
        jest.mocked(useOmniFilterUrlState).mockReturnValue([
            {},
            {},
            jest.fn(),
            mockClearFilterParams,
        ] as any);
        renderWithRouter(<FlowLogsPage />);

        MockOmniFilters.onReset();

        expect(mockClearFilterParams).toHaveBeenCalledTimes(1);
    });

    it('should test <OmniFilters /> sets a new filter param on change', () => {
        const changeEvent = { filterId: 'mock-filter', filters: [] };
        const mockSetFilterParam = jest.fn();
        jest.mocked(useOmniFilterUrlState).mockReturnValue([
            {},
            {},
            mockSetFilterParam,
            jest.fn(),
        ] as any);
        renderWithRouter(<FlowLogsPage />);

        MockOmniFilters.onChange(changeEvent);

        expect(mockSetFilterParam).toHaveBeenCalledWith(
            changeEvent.filterId,
            changeEvent.filters,
            undefined,
        );
    });
});
