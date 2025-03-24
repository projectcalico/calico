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
            total: 1,
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
                page: 1,
            },
        });

        await waitFor(() =>
            expect((result.current as any).data).toEqual({
                pageParams: [1],
                pages: [
                    {
                        items,
                        total: 1,
                        currentPage: 1,
                        nextPage: 2,
                    },
                ],
            }),
        );
    });
});

describe('useFlowLogsStream', () => {
    it('useFlowLogsStream', () => {
        const startStreamMock = jest.fn();
        jest.mocked(useStream).mockReturnValue({
            startStream: startStreamMock,
        } as any);
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('');

        const { rerender } = renderHook(
            ({ params, isDenied }) => useFlowLogsStream(params, isDenied),
            {
                initialProps: {
                    source_name: [],
                } as any,
            },
        );

        const updatedFilters = { source_name: ['foo'] } as any;
        jest.mocked(transformToFlowsFilterQuery).mockReturnValue('fake-query');
        rerender(updatedFilters);

        expect(startStreamMock).toHaveBeenCalledWith(
            `flows?watch=true&filters=fake-query`,
        );
    });
});
