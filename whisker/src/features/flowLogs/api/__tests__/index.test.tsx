import api, { useStream } from '@/api';
import {
    renderHook,
    renderHookWithQueryClient,
    waitFor,
} from '@/test-utils/helper';
import {
    FilterHintTypes,
    ListOmniFilterKeys,
    transformToFlowsFilterQuery,
} from '@/utils/omniFilter';
import {
    useDeniedFlowLogsCount,
    useFlowLogs,
    useFlowLogsStream,
    useInfiniteFilterQuery,
} from '..';

jest.mock('@/api', () => ({
    __esModule: true,
    default: {
        get: jest.fn().mockReturnValue([]),
    },
    useStream: jest.fn(),
}));

jest.mock('@/utils/omniFilter', () => ({
    ...jest.requireActual('@/utils/omniFilter'),
    transformToFlowsFilterQuery: jest.fn(),
}));

describe('useFlowLogs', () => {
    it('should call api get with the expected params', () => {
        renderHookWithQueryClient(useFlowLogs);

        expect(api.get).toHaveBeenCalledWith('flows', {
            queryParams: undefined,
        });
    });
});

describe('useDeniedFlowLogsCount', () => {
    it('should return the count of denied flow logs', async () => {
        jest.mocked(api.get).mockResolvedValueOnce(['foo', 'bar']);

        const { result } = renderHookWithQueryClient(useDeniedFlowLogsCount);

        await waitFor(() => expect(result.current).toEqual(2));
    });
});

describe('useInfiniteFilterQuery', () => {
    it('should return the expected response', async () => {
        const filterString = 'filter-query-string';
        const items = [
            {
                label: 'foo',
                value: 'foo',
            },
        ];
        jest.mocked(api.get).mockResolvedValue({
            items,
            total: {
                totalResults: 1,
            },
        });

        const { result } = renderHookWithQueryClient(() =>
            useInfiniteFilterQuery(
                ListOmniFilterKeys.source_namespace,
                filterString,
            ),
        );

        expect(api.get).toHaveBeenCalledWith('flows-filter-hints', {
            queryParams: {
                filters: filterString,
                type: FilterHintTypes.source_namespace,
                pageSize: 20,
                page: 0,
            },
        });

        await waitFor(() =>
            expect((result.current as any).data).toEqual({
                pageParams: [0],
                pages: [
                    {
                        items,
                        total: 1,
                        currentPage: 0,
                        nextPage: 1,
                    },
                ],
            }),
        );
    });
});

describe('useFlowLogsStream', () => {
    const startTime = new Date();
    const endTime = new Date();

    it('starts the stream with the expected params', () => {
        const startStreamMock = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            startStream: startStreamMock,
            data: [{ start_time: startTime, end_time: endTime }],
        } as any);
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('');

        const { rerender } = renderHook(
            ({ params }) => useFlowLogsStream(15, params),
            {
                initialProps: {
                    source_name: [],
                } as any,
            },
        );

        const updatedFilters = { source_name: ['foo'] } as any;
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('fake-query');
        rerender(updatedFilters);

        expect(startStreamMock).toHaveBeenCalledWith({
            isUpdate: true,
            path: `flows?watch=true&filters=fake-query&startTimeGte=${Math.round(startTime.getTime() / 1000)}`,
        });
    });

    it('calls start stream', () => {
        const startStreamMock = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            startStream: startStreamMock,
            data: [{ start_time: startTime, end_time: endTime }],
        } as any);
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('');

        const { result } = renderHook(() => useFlowLogsStream(15, {}));

        result.current.startStream();

        expect(startStreamMock).toHaveBeenCalledWith({
            path: `flows?watch=true&startTimeGte=${Math.round(startTime.getTime() / 1000)}`,
        });
    });

    it('should reset firstFlowStartTime and update stream when startTime changes', () => {
        const startStreamMock = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            startStream: startStreamMock,
            data: [{ start_time: startTime, end_time: endTime }],
        } as any);
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('');

        const { rerender } = renderHook(
            ({ startTime, filters }) => useFlowLogsStream(startTime, filters),
            {
                initialProps: {
                    startTime: 15,
                    filters: { source_name: [] } as any,
                },
            },
        );

        // Change the startTime parameter
        rerender({
            startTime: 30,
            filters: { source_name: [] } as any,
        });

        // Should call updateStream with the new startTime (30 minutes = -1800 seconds)
        expect(startStreamMock).toHaveBeenCalledWith({
            isUpdate: true,
            path: `flows?watch=true&startTimeGte=-1800`,
        });
    });
});
