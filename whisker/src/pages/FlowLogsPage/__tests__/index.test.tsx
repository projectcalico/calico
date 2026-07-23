import { useFlowLogsStream } from '@/features/flowLogs/api';
import { fireEvent, render, screen } from '@/test-utils/helper';
import FlowLogsPage from '..';

import { useOmniFilterData } from '@/hooks/omniFilters';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { ListOmniFilterKeys, OmniFilterKeys } from '@/utils/omniFilter';
import { act } from 'react';

const MockFlowLogsContainer = {
    onRowClicked: jest.fn(),
    onSortClicked: jest.fn(),
};

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
}));

jest.mock('@/hooks/useFlowLogsUrlFilters', () => ({
    useFlowLogsUrlFilters: jest.fn(),
}));

jest.mock('@/hooks/omniFilters', () => ({ useOmniFilterData: jest.fn() }));

jest.mock(
    '@/features/flowLogs/components/FlowLogsContainer',
    () => (props: any) => {
        MockFlowLogsContainer.onRowClicked = props.onRowClicked;
        MockFlowLogsContainer.onSortClicked = props.onSortClicked;
        return <div>Mock FlowLogsContainer</div>;
    },
);

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
    totalItems: 0,
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
        jest.mocked(useFlowLogsUrlFilters).mockReturnValue({
            filters: {},
            setFilter: jest.fn(),
            clearFilters: jest.fn(),
            setMultiFilter: jest.fn(),
        });
    });

    it('should click play and call startStream', () => {
        const mockStartStream = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            startStream: mockStartStream,
            hasStoppedStreaming: true,
            totalItems: 0,
        });

        render(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Play' }));

        expect(mockStartStream).toHaveBeenCalled();
    });

    it('should click pause and call stopStream', () => {
        const mockStopStream = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            stopStream: mockStopStream,
            isDataStreaming: true,
            totalItems: 0,
        });

        render(<FlowLogsPage />);

        fireEvent.click(screen.getByRole('button', { name: 'Pause' }));

        expect(mockStopStream).toHaveBeenCalled();
    });

    it('should show the waiting state', () => {
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isWaiting: true,
            totalItems: 0,
        });

        render(<FlowLogsPage />);

        expect(screen.getByText('Waiting for flows')).toBeInTheDocument();
    });

    it('should test <OmniFilters /> clears filter params', () => {
        const mockClearFilters = jest.fn();
        jest.mocked(useFlowLogsUrlFilters).mockReturnValue({
            filters: {},
            setFilter: jest.fn(),
            clearFilters: mockClearFilters,
            setMultiFilter: jest.fn(),
        });
        render(<FlowLogsPage />);

        MockOmniFilters.onReset();

        expect(mockClearFilters).toHaveBeenCalledTimes(1);
    });

    it('should test <OmniFilters /> sets a new filter param on change', () => {
        const mockSetFilter = jest.fn();
        jest.mocked(useFlowLogsUrlFilters).mockReturnValue({
            filters: {},
            setFilter: mockSetFilter,
            clearFilters: jest.fn(),
            setMultiFilter: jest.fn(),
        });
        render(<FlowLogsPage />);

        MockOmniFilters.onChange('mock-filter', []);

        expect(mockSetFilter).toHaveBeenCalledWith('mock-filter', []);
    });

    it('should request data for <OmniFilters />', () => {
        const fetchDataMock = jest.fn();
        jest.mocked(useOmniFilterData).mockReturnValue([
            omniFilterData,
            fetchDataMock,
        ]);

        render(<FlowLogsPage />);

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
        render(<FlowLogsPage />);

        MockOmniFilters.onRequestNextPage(filterParam);

        expect(fetchDataMock).toHaveBeenCalledWith(filterParam, null);
    });

    it('should show a toast message when opening a row', () => {
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
            totalItems: 0,
        });
        render(<FlowLogsPage />);

        act(() => MockFlowLogsContainer.onRowClicked({}));

        expect(screen.getByText('Flows stream paused')).toBeInTheDocument();
    });

    it('should show resume the stream when clicking the same row', () => {
        const id = '1234';
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
            totalItems: 0,
        });
        const { rerender } = render(<FlowLogsPage />);

        act(() => MockFlowLogsContainer.onRowClicked({ id }));

        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: false,
            totalItems: 0,
        });

        rerender(<FlowLogsPage />);

        act(() => MockFlowLogsContainer.onRowClicked({ id }));

        expect(screen.getByText('Flows stream resumed.')).toBeInTheDocument();
    });

    it('should not toast when the stream is already paused', () => {
        const id = '1234';
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            hasStoppedStreaming: true,
            totalItems: 0,
        });
        render(<FlowLogsPage />);

        act(() => MockFlowLogsContainer.onRowClicked({ id }));

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
            totalItems: 0,
        });
        render(<FlowLogsPage />);

        act(() => MockFlowLogsContainer.onRowClicked({}));

        expect(
            screen.queryByText('Flows stream paused'),
        ).not.toBeInTheDocument();
    });

    it('should close a virtualized row on sort', () => {
        const closeVirtualizedRowMock = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            isDataStreaming: true,
            totalItems: 0,
        });
        render(<FlowLogsPage />);

        act(() =>
            MockFlowLogsContainer.onRowClicked({
                closeVirtualizedRow: closeVirtualizedRowMock,
            }),
        );
        act(() => MockFlowLogsContainer.onSortClicked());

        expect(closeVirtualizedRowMock).toHaveBeenCalled();
    });
});
