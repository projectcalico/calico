import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    OmniFilterData,
    OmniFilterParam,
    OmniFiltersData,
    SelectedOmniFilterData,
    SelectedOmniFilterOptions,
} from '@/utils/omniFilter';
import React from 'react';

export const useSelectedOmniFilters = (
    urlFilterParams: Record<OmniFilterParam, string[]>,
    omniFilterData: OmniFiltersData,
    selectedOmniFilterData: SelectedOmniFilterData,
) =>
    Object.keys(urlFilterParams as Record<OmniFilterParam, string[]>).reduce(
        (accumulator, current) => {
            const filterId: OmniFilterParam = current as OmniFilterParam;

            const selectedFilters = urlFilterParams[filterId].map(
                (selectedValue) => {
                    let selectedOption = selectedOmniFilterData?.[
                        filterId
                    ]?.filters?.find(
                        (data: OmniFilterOption) =>
                            data.value === selectedValue,
                    );

                    if (selectedOption) {
                        return selectedOption;
                    }

                    selectedOption = omniFilterData[filterId]?.filters?.find(
                        (selectOption) => selectOption.value === selectedValue,
                    ) ?? {
                        label: selectedValue,
                        value: selectedValue,
                    };

                    return selectedOption;
                },
            );

            accumulator[filterId] = selectedFilters;

            return accumulator;
        },
        {} as SelectedOmniFilterOptions,
    );

export const useOmniFilterQuery = (
    filterParam: OmniFilterParam,
): {
    data: OmniFilterData;
    fetchData: (query?: string) => void;
} => {
    const [filterQuery, setFilterQuery] = React.useState<string | null>(null);
    const { data, fetchNextPage, isLoading, isFetchingNextPage } =
        useInfiniteFilterQuery(filterParam, filterQuery);

    const fetchData = (query?: string) => {
        if (query) {
            setFilterQuery(query);
        } else {
            fetchNextPage();
        }
    };

    const filters: OmniFilterOption[] | null =
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

export const useOmniFilterData = (): [
    OmniFiltersData,
    (filterParam: OmniFilterParam, query?: string) => void,
] => {
    const dataQueries = {
        policy: useOmniFilterQuery(OmniFilterParam.policy),
        source_namespace: useOmniFilterQuery(OmniFilterParam.source_namespace),
        dest_namespace: useOmniFilterQuery(OmniFilterParam.dest_namespace),
        source_name: useOmniFilterQuery(OmniFilterParam.source_name),
        dest_name: useOmniFilterQuery(OmniFilterParam.dest_name),
    };

    const fetchData = (filterParam: OmniFilterParam, query?: string) => {
        dataQueries[filterParam].fetchData(query);
    };

    return [
        {
            policy: dataQueries.policy.data,
            source_namespace: dataQueries.source_namespace.data,
            dest_namespace: dataQueries.dest_namespace.data,
            source_name: dataQueries.source_name.data,
            dest_name: dataQueries.dest_name.data,
        },
        fetchData,
    ];
};
