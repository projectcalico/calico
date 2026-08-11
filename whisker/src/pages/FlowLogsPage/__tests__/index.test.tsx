import { useFlowLogsStream } from '@/features/flowLogs/api';
import { fireEvent, render, screen } from '@/test-utils/helper';
import FlowLogsPage from '..';
import { streamButtonStyles, tabStyles } from '../styles';

import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
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

jest.mock(
    '@/features/flowLogs/components/FlowLogsContainer',
    () => (props: any) => {
        MockFlowLogsContainer.onRowClicked = props.onRowClicked;
        MockFlowLogsContainer.onSortClicked = props.onSortClicked;
        return <div>Mock FlowLogsContainer</div>;
    },
);

jest.mock('@/features/flowLogs/components/OmniFilters', () => () => (
    <>MockOmniFilters</>
));

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

describe('FlowLogsPage', () => {
    beforeEach(() => {
        jest.mocked(useFlowLogsStream).mockReturnValue(useStreamStub);
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

    it('should handle a sort click when no row is expanded', () => {
        render(<FlowLogsPage />);

        expect(() =>
            act(() => MockFlowLogsContainer.onSortClicked()),
        ).not.toThrow();
    });

    it('should parse the start time filter and exclude it from the filter hint values', () => {
        jest.mocked(useFlowLogsUrlFilters).mockReturnValue({
            filters: {
                start_time: ['30'],
                source_name: ['foo'],
            } as any,
            setFilter: jest.fn(),
            clearFilters: jest.fn(),
            setMultiFilter: jest.fn(),
        });

        render(<FlowLogsPage />);

        expect(useFlowLogsStream).toHaveBeenCalledWith(30, {
            source_name: ['foo'],
        });
    });

    it('should close an expanded row when the data changes', () => {
        const closeVirtualizedRowMock = jest.fn();
        const { rerender } = render(<FlowLogsPage />);

        act(() =>
            MockFlowLogsContainer.onRowClicked({
                id: '1',
                closeVirtualizedRow: closeVirtualizedRowMock,
            }),
        );

        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            data: [{ start_time: new Date(), end_time: new Date() } as any],
            totalItems: 1,
        });

        rerender(<FlowLogsPage />);

        expect(closeVirtualizedRowMock).toHaveBeenCalled();
    });

    it('should close the expanded row and restart the stream when clicking play', () => {
        const closeVirtualizedRowMock = jest.fn();
        const mockStartStream = jest.fn();
        jest.mocked(useFlowLogsStream).mockReturnValue({
            ...useStreamStub,
            startStream: mockStartStream,
            hasStoppedStreaming: true,
            totalItems: 0,
        });

        render(<FlowLogsPage />);

        act(() =>
            MockFlowLogsContainer.onRowClicked({
                id: '1',
                closeVirtualizedRow: closeVirtualizedRowMock,
            }),
        );

        fireEvent.click(screen.getByRole('button', { name: 'Play' }));

        expect(closeVirtualizedRowMock).toHaveBeenCalled();
        expect(mockStartStream).toHaveBeenCalled();
    });
});

describe('FlowLogsPage styles', () => {
    it('should define the shared button and tab styles', () => {
        expect(streamButtonStyles).toMatchObject({ fontSize: 'sm' });
        expect(tabStyles).toEqual({ fontSize: 'sm' });
    });
});
