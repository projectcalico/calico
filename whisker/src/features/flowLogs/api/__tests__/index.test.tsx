import api, { useStream } from '@/api';
import {
    renderHook,
    renderHookWithQueryClient,
    waitFor,
} from '@/test-utils/helper';
import { OmniFilterParam } from '@/utils/omniFilter';
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
        const items = [
            {
                label: 'foo',
                value: 'bar',
            },
        ];
        jest.mocked(api.get).mockResolvedValue({
            items,
            total: 1,
        });

        const { result } = renderHookWithQueryClient(() =>
            useInfiniteFilterQuery(OmniFilterParam.namespace, {} as any),
        );

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

        const { rerender } = renderHook((props) => useFlowLogsStream(props), {
            initialProps: {
                src_name: [],
            },
        });

        const updatedFilters = { src_name: ['foo'] } as any;
        rerender(updatedFilters);

        expect(startStreamMock).toHaveBeenCalledWith(
            `flows?watch=true&query=${JSON.stringify(updatedFilters)}`,
        );
    });
});
