import {
    OmniFilterOption as ListOmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ApiFilterResponse,
    FilterHintsKeys,
    FilterHintsListKeys,
    FilterHintsQuery,
    FilterHintsQueryList,
    QueryPage,
} from '@/types/api';

export enum CustomOmniFilterParam {
    port = 'port',
}

export enum ListOmniFilterParam {
    policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
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
): FilterHintsQueryList[] => filters.map((value) => ({ type: 'exact', value }));

export const transformToFlowsFilterQuery = (
    omniFilterValues: Record<OmniFilterParam, string[]>,
    filterId?: ListOmniFilterParam,
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
        listFilters[
            OmniFilterProperties[filterId]
                .filterHintsName as FilterHintsListKeys
        ].push({
            type: 'fuzzy',
            value: searchInput,
        });
    }

    const filterHintsQuery: FilterHintsQuery = {
        ...listFilters,
        actions: [],
        protocols: omniFilterValues[OmniFilterParam.protocol],
        dest_ports: OmniFilterProperties[OmniFilterParam.port]
            .transformToApiValues!<number>(
            omniFilterValues[OmniFilterParam.port],
        ),
    };

    return JSON.stringify(filterHintsQuery);
};

export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    {
        selectOptions?: ListOmniFilterOption[];
        defaultOperatorType?: OperatorType;
        label: string;
        limit?: number;
        filterHintsName: FilterHintsKeys;
        transformToApiValues?: <T>(values: string[]) => T[];
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
    port: {
        label: 'Port',
        filterHintsName: 'dest_ports',
        transformToApiValues: <T>(values: string[] | undefined) =>
            values?.map(Number).filter(Boolean) as T[],
    },
    protocol: {
        label: 'Protocol',
        filterHintsName: 'protocols',
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
    items,
    total,
    currentPage: page,
    nextPage: page + 1,
});
