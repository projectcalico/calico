import { useInfiniteFilterQuery } from '@/features/flowLogs/api';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { OmniFilterDataQuery } from '@/types/api';
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
    fetchData: (query?: OmniFilterDataQuery) => void;
} => {
    const [filterQuery, setFilterQuery] =
        React.useState<OmniFilterDataQuery | null>(null);
    const { data, fetchNextPage, isLoading, isFetchingNextPage } =
        useInfiniteFilterQuery(filterParam, filterQuery);

    const fetchData = (query?: OmniFilterDataQuery) => {
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
    (filterParam: OmniFilterParam, query?: OmniFilterDataQuery) => void,
] => {
    const dataQueries = {
        policy: useOmniFilterQuery(OmniFilterParam.policy),
        namespace: useOmniFilterQuery(OmniFilterParam.namespace),
        src_name: useOmniFilterQuery(OmniFilterParam.src_name),
        dst_name: useOmniFilterQuery(OmniFilterParam.dst_name),
    };

    const fetchData = (
        filterParam: OmniFilterParam,
        query?: OmniFilterDataQuery,
    ) => {
        dataQueries[filterParam].fetchData(query);
    };

    return [
        {
            policy: dataQueries.policy.data,
            namespace: dataQueries.namespace.data,
            src_name: dataQueries.src_name.data,
            dst_name: dataQueries.dst_name.data,
        },
        fetchData,
    ];
};
