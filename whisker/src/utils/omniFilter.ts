import {
    OmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ApiFilterResponse,
    FilterHintsListKeys,
    FilterHintsQuery,
    FilterHintsQueryList,
    QueryPage,
} from '@/types/api';

export enum OmniFilterParam {
    policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
}

const transformToListFilter = (
    filters: string[] = [],
): FilterHintsQueryList[] => filters.map((value) => ({ type: 'exact', value }));

export const transformToFlowsFilterQuery = (
    omniFilterValues: Record<OmniFilterParam, string[]>,
    filterId?: OmniFilterParam,
    searchInput?: string,
) => {
    const listFilters = {
        dest_names: transformToListFilter(
            omniFilterValues[OmniFilterParam.dest_name],
        ),
        source_names: transformToListFilter(
            omniFilterValues[OmniFilterParam.source_name],
        ),
        source_namespaces: transformToListFilter(
            omniFilterValues[OmniFilterParam.source_namespace],
        ),
        dest_namespaces: transformToListFilter(
            omniFilterValues[OmniFilterParam.dest_namespace],
        ),
    };

    if (filterId && searchInput) {
        listFilters[OmniFilterProperties[filterId].filterHintsName].push({
            type: 'fuzzy',
            value: searchInput,
        });
    }

    const filterHintsQuery: FilterHintsQuery = {
        ...listFilters,
        actions: [],
        protocols: [],
        dest_ports: [],
    };

    return JSON.stringify(filterHintsQuery);
};

export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    {
        selectOptions?: OmniFilterOption[];
        defaultOperatorType?: OperatorType;
        label: string;
        limit: number;
        filterHintsName: FilterHintsListKeys;
    }
>;

const requestPageSize = 20;

export const OmniFilterProperties: OmniFilterPropertiesType = {
    policy: {
        label: 'Policy',
        limit: requestPageSize,
        filterHintsName: '' as any,
    },
    source_namespace: {
        label: 'Source Namespace',
        limit: requestPageSize,
        filterHintsName: 'source_namespaces',
    },
    dest_namespace: {
        label: 'Destination Namespace',
        limit: requestPageSize,
        filterHintsName: 'dest_namespaces',
    },
    source_name: {
        label: 'Source',
        limit: requestPageSize,
        filterHintsName: 'source_names',
    },
    dest_name: {
        label: 'Destination',
        limit: requestPageSize,
        filterHintsName: 'dest_names',
    },
};

export type OmniFiltersData = Record<OmniFilterParam, OmniFilterData>;

export type OmniFilterData = {
    filters: OmniFilterOption[] | null;
    isLoading: boolean;
    total?: number;
};

export type SelectedOmniFilterData = Partial<OmniFiltersData>;

export type SelectedOmniFilters = Partial<Record<OmniFilterParam, string[]>>;

export type SelectedOmniFilterOptions = Record<
    OmniFilterParam,
    OmniFilterOption[]
>;

export const transformToQueryPage = (
    { items, total }: ApiFilterResponse,
    page: number,
): QueryPage => ({
    items,
    total,
    currentPage: page,
    nextPage: page + 1,
});
