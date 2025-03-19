import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import { OmniFilterOption as ListOmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ListOmniFilterParam,
    ListOmniFilterData,
    OmniFilterParam,
    ListOmniFiltersData,
    SelectedOmniFilterData,
    SelectedOmniFilterOptions,
} from '@/utils/omniFilter';
import React from 'react';

export const useSelectedListOmniFilters = (
    urlFilterParams: Record<OmniFilterParam, string[]>,
    omniFilterData: ListOmniFiltersData,
    selectedOmniFilterData: SelectedOmniFilterData,
) => {
    const urlFilterValueKeys = Object.keys(urlFilterParams).filter(
        (key) => ListOmniFilterParam[key as ListOmniFilterParam],
    );

    return urlFilterValueKeys.reduce((accumulator, current) => {
        const filterId = current as ListOmniFilterParam;

        const selectedFilters = urlFilterParams[filterId].map(
            (selectedValue) => {
                let selectedOption = selectedOmniFilterData?.[
                    filterId
                ]?.filters?.find(
                    (data: ListOmniFilterOption) =>
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
    }, {} as SelectedOmniFilterOptions);
};

export const useOmniFilterQuery = (
    filterParam: ListOmniFilterParam,
): {
    data: ListOmniFilterData;
    fetchData: (query: string | null) => void;
} => {
    const [filterQuery, setFilterQuery] = React.useState<string | null>(null);
    const { data, fetchNextPage, isLoading, isFetchingNextPage } =
        useInfiniteFilterQuery(filterParam, filterQuery);

    const fetchData = (query: string | null) => {
        if (query !== null) {
            setFilterQuery(query);
        } else {
            fetchNextPage();
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

export const useOmniFilterData = (): [
    ListOmniFiltersData,
    (filterParam: ListOmniFilterParam, query: string | null) => void,
] => {
    const dataQueries = {
        policy: useOmniFilterQuery(ListOmniFilterParam.policy),
        source_namespace: useOmniFilterQuery(
            ListOmniFilterParam.source_namespace,
        ),
        dest_namespace: useOmniFilterQuery(ListOmniFilterParam.dest_namespace),
        source_name: useOmniFilterQuery(ListOmniFilterParam.source_name),
        dest_name: useOmniFilterQuery(ListOmniFilterParam.dest_name),
    };

    const fetchData = (
        filterParam: ListOmniFilterParam,
        query: string | null,
    ) => {
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
