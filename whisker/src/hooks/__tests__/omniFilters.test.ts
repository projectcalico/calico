import { renderHook } from '@/test-utils/helper';
import { useSelectedOmniFilters } from '..';
import {
    OmniFilterParam,
    OmniFiltersData,
    SelectedOmniFilterData,
} from '@/utils/omniFilter';
import { useOmniFilterData } from '../omniFilters';
import { useInfiniteFilterQuery } from '@/features/flowLogs/api';

jest.mock('@/features/flowLogs/api', () => ({
    useInfiniteFilterQuery: jest.fn(),
}));

const urlFilterParams: Record<OmniFilterParam, string[]> = {
    namespace: ['foo'],
    policy: [],
    src_name: [],
    dst_name: [],
};
const omniFilterData: OmniFiltersData = {
    namespace: {
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
    dst_name: {
        filters: [],
        isLoading: false,
    },
    src_name: {
        filters: [],
        isLoading: false,
    },
};
const selectedOmniFilterData: SelectedOmniFilterData = {
    namespace: {
        filters: [{ label: 'Foo', value: 'foo' }],
        isLoading: false,
        total: 0,
    },
};

describe('useSelectedOmniFilters', () => {
    it('should get selected option from selectedOmniFilterData', () => {
        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dst_name: [],
            src_name: [],
        });
    });

    it('should get selected option from omniFilterData', () => {
        const selectedOmniFilterData: SelectedOmniFilterData = {
            namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dst_name: [],
            src_name: [],
        });
    });

    it('should create an option from the value when there is no option omniFilterData', () => {
        const omniFilterData: OmniFiltersData = {
            namespace: {
                filters: [],
                isLoading: false,
            },
            policy: {
                filters: [],
                isLoading: false,
            },
            dst_name: {
                filters: [],
                isLoading: false,
            },
            src_name: {
                filters: [],
                isLoading: false,
            },
        };
        const selectedOmniFilterData: SelectedOmniFilterData = {
            namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        };

        const { result } = renderHook(() =>
            useSelectedOmniFilters(
                urlFilterParams,
                omniFilterData,
                selectedOmniFilterData,
            ),
        );

        expect(result.current).toEqual({
            namespace: [{ label: 'foo', value: 'foo' }],
            policy: [],
            dst_name: [],
            src_name: [],
        });
    });
});

describe('useOmniFilterData', () => {
    const hookResponse = {
        data: {
            pageParams: [],
            pages: [],
        },
        fetchNextPage: jest.fn(),
        isLoading: false,
        isFetchingNextPage: false,
    } as any;

    it('should ', () => {
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
            namespace: {
                filters: [],
                isLoading: false,
                total: 0,
            },
            src_name: {
                filters: [],
                isLoading: false,
                total: 0,
            },
            dst_name: {
                filters: [],
                isLoading: false,
                total: 0,
            },
        });
    });

    it('should fetch the next page', () => {
        const fetchNextPageMock = jest.fn();
        const hookResponse = {
            data: {
                pageParams: [],
                pages: [],
            },
            fetchNextPage: fetchNextPageMock,
            isLoading: false,
            isFetchingNextPage: false,
        } as any;
        jest.mocked(useInfiniteFilterQuery).mockReturnValue(hookResponse);

        const { result } = renderHook(() => useOmniFilterData());

        result.current[1](OmniFilterParam.namespace);

        expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
    });
});
