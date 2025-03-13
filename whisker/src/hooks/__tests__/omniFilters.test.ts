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
    dest_namespace: ['foo'],
    policy: [],
    source_name: [],
    dest_name: [],
    source_namespace: [],
};
const omniFilterData: OmniFiltersData = {
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
            dest_namespace: [{ label: 'Foo', value: 'foo' }],
            policy: [],
            dest_name: [],
            source_name: [],
            source_namespace: [],
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
            useSelectedOmniFilters(
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
        });
    });

    it('should create an option from the value when there is no option omniFilterData', () => {
        const omniFilterData: OmniFiltersData = {
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
            useSelectedOmniFilters(
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

    it('should return the expected data', () => {
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

        result.current[1](OmniFilterParam.source_namespace);

        expect(fetchNextPageMock).toHaveBeenCalledTimes(1);
    });
});
