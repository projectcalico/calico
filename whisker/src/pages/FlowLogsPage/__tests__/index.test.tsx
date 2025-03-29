import {
    useDeniedFlowLogsCount,
    useFlowLogsCount,
    useFlowLogsStream,
} from '@/features/flowLogs/api';
import { useOmniFilterUrlState } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { fireEvent, renderWithRouter, screen } from '@/test-utils/helper';
import FlowLogsPage from '..';

import { useOmniFilterData } from '@/hooks/omniFilters';
import { ListOmniFilterKeys, OmniFilterKeys } from '@/utils/omniFilter';
import { act } from 'react';
import { MemoryRouter } from 'react-router-dom';

const MockOutlet = {
    onRowClicked: jest.fn(),
    onSortClicked: jest.fn(),
};

jest.mock('react-router-dom', () => ({
    ...jest.requireActual('react-router-dom'),
    Outlet: ({ context }: any) => {
        MockOutlet.onRowClicked = context.onRowClicked;
        MockOutlet.onSortClicked = context.onSortClicked;
        return <>Flow logs view: {context.view}</>;
    },
}));

jest.mock('@/features/flowLogs/api', () => ({
    useDeniedFlowLogsCount: jest.fn(),
    useFlowLogsCount: jest.fn(),
    useFlowLogsStream: jest.fn(),
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

jest.mock('@/hooks/omniFilters', () => ({ useOmniFilterData: jest.fn() }));

const MockOmniFilters = {
    onReset: jest.fn(),
    onChange: jest.fn(),
    onRequestFilterData: jest.fn(),
    onRequestNextPage: jest.fn(),
};

jest.mock(
    '@/features/flowLogs/components/OmniFilters',
    () =>
        ({
            onReset,
            onChange,
            onRequestFilterData,
            onRequestNextPage,
        }: any) => {
            MockOmniFilters.onReset = onReset;
            MockOmniFilters.onChange = onChange;
            MockOmniFilters.onRequestFilterData = onRequestFilterData;
            MockOmniFilters.onRequestNextPage = onRequestNextPage;
            return <>MockOmniFilters</>;
        },
);

jest.mock('@/hooks', () => ({ useSelectedListOmniFilters: jest.fn() }));

const useStreamStub = {
    stopStream: jest.fn(),
    startStream: jest.fn(),
    data: [],
    error: null,
    isDataStreaming: false,
    isWaiting: false,
    hasStoppedStreaming: false,
    isFetching: false,
};

const omniFilterData = {
    namespace: {
        filters: [],
        isLoading: false,
    },
    policy: {
        filters: [],
        isLoading: false,
    },
    source_name: {
        filters: [],
        isLoading: false,
    },
    source_namespace: {
        filters: [],
        isLoading: false,
    },
    dest_name: {
        filters: [],
        isLoading: false,
    },
    dest_namespace: {
        filters: [],
        isLoading: false,
    },
};

describe('FlowLogsPage', () => {
    beforeEach(() => {
        jest.mocked(useFlowLogsStream).mockReturnValue(useStreamStub);
        jest.mocked(useOmniFilterData).mockReturnValue([
            omniFilterData,
            jest.fn(),
        ]);
        jest.mocked(useOmniFilterUrlState).mockReturnValue([
            {},
            {},
            jest.fn(),
            jest.fn(),
            jest.fn(),
        ] as any);
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
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            startStream: mockStartStream,
            hasStoppedStreaming: true,
        });

        renderWithRouter(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Play' }));

        expect(mockStartStream).toHaveBeenCalled();
    });

    it('should click pause and call stopStream', () => {
        const mockStopStream = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            stopStream: mockStopStream,
            isDataStreaming: true,
        });

        renderWithRouter(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

        expect(mockStopStream).toHaveBeenCalled();
    });

    it('should show the waiting state', () => {
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isWaiting: true,
        });

        renderWithRouter(<FlowLogsPage />);

        expect(screen.getByText('Waiting for flows')).toBeInTheDocument();
    });

    it('should test <OmniFilters /> clears filter params', () => {
        const mockClearFilterParams = jest.fn();
        jest.mocked(useOmniFilterUrlState).mockReturnValue([
            {},
            {},
            jest.fn(),
            mockClearFilterParams,
            jest.fn(),
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

    it('should request data for <OmniFilters />', () => {
        const fetchDataMock = jest.fn();
        jest.mocked(useOmniFilterData).mockReturnValue([
            omniFilterData,
            fetchDataMock,
        ]);

        renderWithRouter(<FlowLogsPage />);

        const userText = 'user-text';
        MockOmniFilters.onRequestFilterData({
            filterParam: OmniFilterKeys.dest_namespace,
            searchOption: userText,
        });

        expect(fetchDataMock).toHaveBeenCalledWith(
            ListOmniFilterKeys.dest_namespace,
            JSON.stringify({
                dest_namespaces: [{ type: 'Fuzzy', value: userText }],
            }),
        );
    });

    it('should fetch the next page for <OmniFilters />', () => {
        const filterParam = 'xyz';
        const fetchDataMock = jest.fn();
        jest.mocked(useOmniFilterData).mockReturnValue([
            omniFilterData,
            fetchDataMock,
        ]);
        renderWithRouter(<FlowLogsPage />);

        MockOmniFilters.onRequestNextPage(filterParam);

        expect(fetchDataMock).toHaveBeenCalledWith(filterParam, null);
    });

    it('should show a toast message when opening a row', () => {
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
        });
        renderWithRouter(<FlowLogsPage />);

        act(() => MockOutlet.onRowClicked({}));

        expect(screen.getByText('Flows stream paused')).toBeInTheDocument();
    });

    it('should show resume the stream when clicking the same row', () => {
        const id = '1234';
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
        });
        const { rerender } = renderWithRouter(<FlowLogsPage />);

        act(() => MockOutlet.onRowClicked({ id }));

        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: false,
        });

        rerender(
            <MemoryRouter>
                <FlowLogsPage />
            </MemoryRouter>,
        );

        act(() => MockOutlet.onRowClicked({ id }));

        expect(screen.getByText('Flows stream resumed.')).toBeInTheDocument();
    });

    it('should not toast when the stream is already paused', () => {
        const id = '1234';
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            hasStoppedStreaming: true,
        });
        renderWithRouter(<FlowLogsPage />);

        act(() => MockOutlet.onRowClicked({ id }));

        expect(
            screen.queryByText('Flows stream resumed.'),
        ).not.toBeInTheDocument();
        expect(
            screen.queryByText('Flows stream paused'),
        ).not.toBeInTheDocument();
    });

    it('should not show a toast message when opening another row', () => {
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: false,
        });
        renderWithRouter(<FlowLogsPage />);

        act(() => MockOutlet.onRowClicked({}));

        expect(
            screen.queryByText('Flows stream paused'),
        ).not.toBeInTheDocument();
    });

    it('should close a virtualized row on sort', () => {
        const closeVirtualizedRowMock = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
        });
        renderWithRouter(<FlowLogsPage />);

        act(() =>
            MockOutlet.onRowClicked({
                closeVirtualizedRow: closeVirtualizedRowMock,
            }),
        );
        act(() => MockOutlet.onSortClicked());

        expect(closeVirtualizedRowMock).toHaveBeenCalled();
    });
});
