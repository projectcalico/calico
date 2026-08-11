import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import { useDebouncedCallback } from '@/hooks';
import { useFlowLogsUrlFilters } from '@/hooks/useFlowLogsUrlFilters';
import { OmniFilterOption as ListOmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    FilterHintKey,
    ListOmniFilterData,
    toHintFilterQuery,
} from '@/utils/omniFilter';
import React from 'react';

export const useOmniFilterQuery = (
    filterParam: FilterHintKey,
): {
    data: ListOmniFilterData;
    fetchData: (query: string | null) => void;
} => {
    const [filterQuery, setFilterQuery] = React.useState<string | null>(null);
    const { data, fetchNextPage, isLoading, isFetchingNextPage, refetch } =
        useInfiniteFilterQuery(filterParam, filterQuery);

    const fetchData = (query: string | null) => {
        if (query === null) {
            fetchNextPage();
        } else if (query === filterQuery) {
            refetch();
        } else {
            setFilterQuery(query);
        }
    };

    const filters: ListOmniFilterOption[] | null =
        data?.pages.flatMap(({ items }) => items) ?? null;

    return {
        data: {
            filters,
            isLoading: isLoading || isFetchingNextPage,
            total: data?.pages[0]?.total ?? 0,
        },
        fetchData,
    };
};

/**
 * Fetches the selectable options for a filter from flows-filter-hints,
 * reading the current URL filter state directly so filter components can
 * fetch their own data. Options are narrowed by the other active filters —
 * the filter's own selection is excluded so users can widen it.
 */
export const useOmniFilterOptions = (
    filterId: FilterHintKey,
    { narrowByActiveFilters = true }: { narrowByActiveFilters?: boolean } = {},
) => {
    const { filters } = useFlowLogsUrlFilters();
    const { data, fetchData } = useOmniFilterQuery(filterId);
    const debounce = useDebouncedCallback();
    const [isTyping, setIsTyping] = React.useState(false);

    const requestOptions = (searchOption?: string) =>
        fetchData(
            toHintFilterQuery(
                narrowByActiveFilters ? filters : {},
                filterId,
                searchOption || undefined,
            ),
        );

    const requestSearch = (searchOption: string) => {
        const requestData = () => {
            requestOptions(searchOption);
            setIsTyping(false);
        };

        if (searchOption.length >= 1) {
            setIsTyping(true);
            debounce(searchOption, requestData);
        } else {
            requestData();
        }
    };

    const requestNextPage = () => fetchData(null);

    return {
        options: data.filters,
        isLoading: data.isLoading || isTyping,
        total: data.total,
        requestOptions,
        requestSearch,
        requestNextPage,
    };
};
