import { act, renderHook, waitFor } from '@/test-utils/helper';
import { useSelectedListOmniFilters } from '..';
import {
    OmniFilterParam,
    ListOmniFiltersData,
    SelectedOmniFilterData,
    ListOmniFilterKeys,
} from '@/utils/omniFilter';
import { useOmniFilterData } from '../omniFilters';
import { useInfiniteFilterQuery } from '@/features/flowLogs/api';

jest.mock('@/features/flowLogs/api', () => ({
    useInfiniteFilterQuery: jest.fn(),
}));

const urlFilterParams: Record<OmniFilterParam, string[]> = {
    dest_namespace: ['foo'],
    policy: [],
    source_name: [],
    dest_name: [],
    source_namespace: [],
    dest_port: [],
    protocol: [],
    policyV2: [],
    policyV2Namespace: [],
    policyV2Tier: [],
    policyV2Kind: [],
    reporter: [],
    start_time: [],
};
const omniFilterData: ListOmniFiltersData = {
    dest_namespace: {
        filters: [
            { label: 'Foo', value: 'foo' },
            { label: 'Bar', value: 'bar' },
        ],
        isLoading: false,
    },
    policy: {
        filters: [],
        isLoading: false,
    },
    dest_name: {
        filters: [],
        isLoading: false,
    },
    source_namespace: {
        filters: [],
        isLoading: false,
    },
    source_name: {
        filters: [],
        isLoading: false,
    },
};
const selectedOmniFilterData: SelectedOmniFilterData = {
    dest_namespace: {
        filters: [{ label: 'Foo', value: 'foo' }],
        isLoading: false,
        total: 0,
    },
};

describe('useSelectedListOmniFilters', () => {
    it('should get selected option from selectedOmniFilterData', () => {
        const { result } = renderHook(() =>
            useSelectedListOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            dest_namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dest_name: [],
            source_name: [],
            source_namespace: [],
            reporter: [],
        });
    });

    it('should get selected option from omniFilterData', () => {
        const selectedOmniFilterData: SelectedOmniFilterData = {
            dest_namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedListOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            dest_namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dest_name: [],
            source_name: [],
            source_namespace: [],
            reporter: [],
        });
    });

    it('should create an option from the value when there is no option omniFilterData', () => {
        const omniFilterData: ListOmniFiltersData = {
            source_namespace: {
                filters: [],
                isLoading: false,
            },
            dest_namespace: {
                filters: [],
                isLoading: false,
            },
            policy: {
                filters: [],
                isLoading: false,
            },
            dest_name: {
                filters: [],
                isLoading: false,
            },
            source_name: {
                filters: [],
                isLoading: false,
            },
        };
        const selectedOmniFilterData: SelectedOmniFilterData = {
            source_namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedListOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            dest_namespace: [{ label: 'foo', value: 'foo' }],
            policy: [],
            dest_name: [],
            source_name: [],
            source_namespace: [],
            reporter: [],
        });
    });
});

describe('useOmniFilterData', () => {
    it('should return the expected data', () => {
        const hookResponse = {
            data: {
                pageParams: [],
                pages: [],
            },
            fetchNextPage: jest.fn(),
            refetch: jest.fn(),
            isLoading: false,
            isFetchingNextPage: false,
        } as any;
        jest.mocked(useInfiniteFilterQuery).mockImplementation(
            (filterParam) => {
                if (filterParam === 'policy') {
                    return {
                        ...hookResponse,
                        data: {
                            pageParams: [],
                            pages: [
                                {
                                    items: [{ label: 'page 1', value: 'pg-1' }],
                                },
                                {
                                    items: [{ label: 'page 2', value: 'pg-2' }],
                                },
                            ],
                        },
                    } as any;
                }

                return hookResponse;
            },
        );

        const { result } = renderHook(() => useOmniFilterData());

        expect(result.current[0]).toEqual({
            policy: {
                filters: [
                    { label: 'page 1', value: 'pg-1' },
                    { label: 'page 2', value: 'pg-2' },
                ],
                isLoading: false,
                total: 0,
            },
            source_namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
            dest_namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
            source_name: {
                filters: [],
                isLoading: false,
                total: 0,
            },
            dest_name: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        });

        expect(hookResponse.fetchNextPage).not.toHaveBeenCalled();
        expect(hookResponse.refetch).not.toHaveBeenCalled();
    });

    it('should fetch the next page', () => {
        const fetchNextPageMock = jest.fn();
        const hookResponse = {
            data: {
                pageParams: [],
                pages: [],
            },
            fetchNextPage: fetchNextPageMock,
            refetch: jest.fn(),
            isLoading: false,
            isFetchingNextPage: false,
        } as any;
        jest.mocked(useInfiniteFilterQuery).mockReturnValue(hookResponse);

        const { result } = renderHook(() => useOmniFilterData());

        result.current[1](ListOmniFilterKeys.source_namespace, null);

        expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
    });

    it('should refetch when the same query is passed', async () => {
        const refetchMock = jest.fn();
        const hookResponse = {
            data: {
                pageParams: [],
                pages: [],
            },
            fetchNextPage: jest.fn(),
            refetch: refetchMock,
            isLoading: false,
            isFetchingNextPage: false,
        } as any;
        jest.mocked(useInfiniteFilterQuery).mockReturnValue(hookResponse);

        const { result, rerender } = renderHook(() => useOmniFilterData());

        act(() =>
            result.current[1](ListOmniFilterKeys.source_namespace, 'foo'),
        );

        rerender();

        act(() =>
            result.current[1](ListOmniFilterKeys.source_namespace, 'foo'),
        );

        await waitFor(() => expect(refetchMock).toHaveBeenCalledTimes(1));
    });
});
