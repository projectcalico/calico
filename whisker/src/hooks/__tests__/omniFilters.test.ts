import { act, renderHookWithRouter, waitFor } from '@/test-utils/helper';
import { renderHook } from '@testing-library/react';
import { ListOmniFilterKeys } from '@/utils/omniFilter';
import { useOmniFilterOptions, useOmniFilterQuery } from '../omniFilters';
import { useInfiniteFilterQuery } from '@/features/flowLogs/api';

jest.mock('@/features/flowLogs/api', () => ({
    useInfiniteFilterQuery: jest.fn(),
}));

const queryResponse = {
    data: undefined,
    fetchNextPage: jest.fn(),
    refetch: jest.fn(),
    isLoading: false,
    isFetchingNextPage: false,
} as any;

describe('useOmniFilterQuery', () => {
    it('should return null filters and a total of 0 when there is no data', () => {
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            isLoading: true,
        });

        const { result } = renderHook(() =>
            useOmniFilterQuery(ListOmniFilterKeys.source_namespace),
        );

        expect(result.current.data).toEqual({
            filters: null,
            isLoading: true,
            total: 0,
        });
    });

    it('should flatten the pages into filters and return the total', () => {
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            data: {
                pageParams: [],
                pages: [
                    {
                        items: [{ label: 'Foo', value: 'foo' }],
                        total: 3,
                    },
                    {
                        items: [
                            { label: 'Bar', value: 'bar' },
                            { label: 'Baz', value: 'baz' },
                        ],
                        total: 3,
                    },
                ],
            },
        });

        const { result } = renderHook(() =>
            useOmniFilterQuery(ListOmniFilterKeys.source_namespace),
        );

        expect(result.current.data).toEqual({
            filters: [
                { label: 'Foo', value: 'foo' },
                { label: 'Bar', value: 'bar' },
                { label: 'Baz', value: 'baz' },
            ],
            isLoading: false,
            total: 3,
        });
    });
});

describe('useOmniFilterOptions', () => {
    const lastRequestedQuery = () => {
        const [filterId, query] =
            jest.mocked(useInfiniteFilterQuery).mock.lastCall!;
        return { filterId, query };
    };

    beforeEach(() => {
        jest.mocked(useInfiniteFilterQuery).mockReturnValue(queryResponse);
    });

    it('should narrow the request by other active filters, excluding its own selection', () => {
        const { result } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/?source_namespace=default&dest_name=api'] },
        );

        act(() => result.current.requestOptions(''));

        const { filterId, query } = lastRequestedQuery();
        expect(filterId).toBe('source_namespace');
        expect(JSON.parse(query!)).toEqual({
            dest_names: [{ type: 'Exact', value: 'api' }],
        });
    });

    it('should include the search term as a fuzzy match', () => {
        const { result } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/?dest_name=api'] },
        );

        act(() => result.current.requestOptions('kube'));

        expect(JSON.parse(lastRequestedQuery().query!)).toEqual({
            dest_names: [{ type: 'Exact', value: 'api' }],
            source_namespaces: [{ type: 'Fuzzy', value: 'kube' }],
        });
    });

    it('should not contribute start_time to the request', () => {
        const { result } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/?start_time=15'] },
        );

        act(() => result.current.requestOptions(''));

        expect(lastRequestedQuery().query).toBe('');
    });

    it('should ignore active filters when narrowByActiveFilters is false', () => {
        const { result } = renderHookWithRouter(
            () =>
                useOmniFilterOptions('policyName', {
                    narrowByActiveFilters: false,
                }),
            { routes: ['/?dest_name=api'] },
        );

        act(() => result.current.requestOptions('allow'));

        const { filterId, query } = lastRequestedQuery();
        expect(filterId).toBe('policyName');
        expect(JSON.parse(query!)).toEqual({
            policies: [{ name: { type: 'Fuzzy', value: 'allow' } }],
        });
    });

    it('should fetch the next page', () => {
        const fetchNextPageMock = jest.fn();
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            fetchNextPage: fetchNextPageMock,
        });

        const { result } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/'] },
        );

        result.current.requestNextPage();

        expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
    });

    it('should refetch when the same options are requested again', async () => {
        const refetchMock = jest.fn();
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            refetch: refetchMock,
        });

        const { result, rerender } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/'] },
        );

        act(() => result.current.requestOptions(''));
        rerender();
        act(() => result.current.requestOptions(''));

        await waitFor(() => expect(refetchMock).toHaveBeenCalledTimes(1));
    });

    it('should expose the fetched options, loading state and total', () => {
        jest.mocked(useInfiniteFilterQuery).mockReturnValue({
            ...queryResponse,
            data: {
                pageParams: [],
                pages: [
                    { items: [{ label: 'Foo', value: 'foo' }], total: 1 },
                ],
            },
        });

        const { result } = renderHookWithRouter(
            () => useOmniFilterOptions(ListOmniFilterKeys.source_namespace),
            { routes: ['/'] },
        );

        expect(result.current.options).toEqual([
            { label: 'Foo', value: 'foo' },
        ]);
        expect(result.current.isLoading).toBe(false);
        expect(result.current.total).toBe(1);
    });
});
