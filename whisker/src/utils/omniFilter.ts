import {
    OmniFilterOption as ListOmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ApiFilterResponse,
    FilterHintQueriesKeys,
    FilterHintsRequest,
    FilterHintQuery,
    QueryPage,
} from '@/types/api';

export enum CustomOmniFilterParam {
    port = 'port',
}

export enum ListOmniFilterParam {
    policy = 'policy',
    source_namespace = 'source_namespace',
    source_name = 'source_name',
    dest_namespace = 'dest_namespace',
    dest_name = 'dest_name',
}

export enum OmniFilterParam {
    policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
    protocol = 'protocol',
    port = 'port',
}

const transformToListFilter = (
    filters: string[] = [],
): FilterHintQuery[] | undefined =>
    filters.length
        ? filters.map((value) => ({
              type: 'Exact',
              value,
          }))
        : undefined;

export const transformToFlowsFilterQuery = (
    omniFilterValues: Record<OmniFilterParam, string[]>,
    listFilterId?: ListOmniFilterParam,
    searchInput?: string,
) => {
    const filterHintsQuery: FilterHintsRequest = Object.keys(
        omniFilterValues,
    ).reduce((acc, filterKey) => {
        const filterId = filterKey as ListOmniFilterParam;
        const key = OmniFilterProperties[filterId].filterHintsKey;

        return listFilterId === filterId
            ? acc
            : {
                  ...acc,
                  [key]: OmniFilterProperties[
                      filterId
                  ].transformToFilterHintRequest(omniFilterValues[filterId]),
              };
    }, {});

    if (listFilterId && searchInput) {
        const key = OmniFilterProperties[listFilterId].filterHintsKey;
        filterHintsQuery[key] = [
            {
                type: 'Fuzzy',
                value: searchInput,
            },
        ];
    }

    return Object.keys(filterHintsQuery).length
        ? JSON.stringify(filterHintsQuery)
        : '';
};

export type FilterHintType =
    | 'SourceName'
    | 'DestName'
    | 'DestNamespace'
    | 'SourceNamespace'
    | 'PolicyTier';

export const FilterHintTypes: Record<ListOmniFilterParam, FilterHintType> = {
    [ListOmniFilterParam.dest_name]: 'DestName',
    [ListOmniFilterParam.dest_namespace]: 'DestNamespace',
    [ListOmniFilterParam.source_name]: 'SourceName',
    [ListOmniFilterParam.source_namespace]: 'SourceNamespace',
    [ListOmniFilterParam.policy]: 'PolicyTier',
};

export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    {
        selectOptions?: ListOmniFilterOption[];
        defaultOperatorType?: OperatorType;
        label: string;
        limit?: number;
        filterHintsKey: FilterHintQueriesKeys;
        transformToFilterHintRequest: (
            filters: string[],
        ) => FilterHintQuery[] | undefined;
    }
>;

const requestPageSize = 20;

export const OmniFilterProperties: OmniFilterPropertiesType = {
    policy: {
        label: 'Policy',
        limit: requestPageSize,
        filterHintsKey: 'policies',
        transformToFilterHintRequest: transformToListFilter,
    },
    source_namespace: {
        label: 'Source Namespace',
        limit: requestPageSize,
        filterHintsKey: 'source_namespaces',
        transformToFilterHintRequest: transformToListFilter,
    },
    dest_namespace: {
        label: 'Destination Namespace',
        limit: requestPageSize,
        filterHintsKey: 'dest_namespaces',
        transformToFilterHintRequest: transformToListFilter,
    },
    source_name: {
        label: 'Source',
        limit: requestPageSize,
        filterHintsKey: 'source_names',
        transformToFilterHintRequest: transformToListFilter,
    },
    dest_name: {
        label: 'Destination',
        limit: requestPageSize,
        filterHintsKey: 'dest_names',
        transformToFilterHintRequest: transformToListFilter,
    },
    port: {
        label: 'Port',
        filterHintsKey: 'dest_ports',
        transformToFilterHintRequest: (values: string[]) =>
            values.length
                ? values
                      .map(Number)
                      .filter(Boolean)
                      .map((value) => ({ type: 'Exact', value }))
                : undefined,
    },
    protocol: {
        label: 'Protocol',
        filterHintsKey: 'protocols',
        transformToFilterHintRequest: transformToListFilter,
    },
};

export type ListOmniFiltersData = Record<
    ListOmniFilterParam,
    ListOmniFilterData
>;

export type ListOmniFilterData = {
    filters: ListOmniFilterOption[] | null;
    isLoading: boolean;
    total?: number;
};

export type SelectedOmniFilterData = Partial<ListOmniFiltersData>;

export type SelectedOmniFilters = Partial<Record<OmniFilterParam, string[]>>;

export type SelectedOmniFilterOptions = Record<
    ListOmniFilterParam,
    ListOmniFilterOption[]
>;

export const transformToQueryPage = (
    { items, total }: ApiFilterResponse,
    page: number,
): QueryPage => ({
    items: items.map(({ value }) => ({ label: value, value })),
    total,
    currentPage: page,
    nextPage: page + 1,
});
