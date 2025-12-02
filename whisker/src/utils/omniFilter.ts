import { OmniFilterProps } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import {
    OmniFilterOption as ListOmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ApiFilterResponse,
    FlowsFilterKeys,
    FlowsFilter,
    FlowsFilterQuery,
    QueryPage,
    FlowsFilterValue,
} from '@/types/api';
import { FilterHintValues, ReporterLabels } from '@/types/render';

export enum FilterKey {
    // policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
    protocol = 'protocol',
    dest_port = 'dest_port',
    policy = 'policy',
    policyNamespace = 'policyNamespace',
    policyTier = 'policyTier',
    policyKind = 'policyKind',
    reporter = 'reporter',
    start_time = 'start_time',
    action = 'action',
    staged_action = 'staged_action',
    pending_action = 'pending_action',
}

export type FilterProperty = {
    filterHintsKey: FlowsFilterKeys;
    transformToFilterHintRequest: (
        filters: string[],
    ) => FlowsFilterQuery[] | undefined | string[];
};

export const ListOmniFilterKeys: Omit<
    typeof FilterKey,
    | 'protocol'
    | 'dest_port'
    | 'policy'
    | 'policyNamespace'
    | 'policyTier'
    | 'policyKind'
    | 'start_time'
    | 'action'
    | 'staged_action'
    | 'pending_action'
> = {
    // [FilterKey.policy]: FilterKey.policy,
    [FilterKey.source_namespace]: FilterKey.source_namespace,
    [FilterKey.source_name]: FilterKey.source_name,
    [FilterKey.dest_namespace]: FilterKey.dest_namespace,
    [FilterKey.dest_name]: FilterKey.dest_name,
    [FilterKey.reporter]: FilterKey.reporter,
} as const;

export type DataListOmniFilterParam = keyof Omit<
    typeof ListOmniFilterKeys,
    'reporter'
>;

export const FilterHintKeys: Omit<
    typeof FilterKey,
    | 'protocol'
    | 'dest_port'
    | 'start_time'
    | 'action'
    | 'staged_action'
    | 'pending_action'
> = {
    // [FilterKey.policy]: FilterKey.policy,
    [FilterKey.source_namespace]: FilterKey.source_namespace,
    [FilterKey.source_name]: FilterKey.source_name,
    [FilterKey.dest_namespace]: FilterKey.dest_namespace,
    [FilterKey.dest_name]: FilterKey.dest_name,
    [FilterKey.policyTier]: FilterKey.policyTier,
    [FilterKey.policyNamespace]: FilterKey.policyNamespace,
    [FilterKey.policyKind]: FilterKey.policyKind,
    [FilterKey.policy]: FilterKey.policy,
    [FilterKey.reporter]: FilterKey.reporter,
} as const;
export type FilterHintKey = keyof typeof FilterHintKeys;

export const StreamFilterKeys = {
    [FilterKey.start_time]: FilterKey.start_time,
} as const;

export type StreamFilterKey = keyof typeof StreamFilterKeys;

export const OmniFilterKeys = {
    ...ListOmniFilterKeys,
    [FilterKey.dest_port]: FilterKey.dest_port,
    [FilterKey.protocol]: FilterKey.protocol,
    [FilterKey.policy]: FilterKey.policy,
    [FilterKey.policyNamespace]: FilterKey.policyNamespace,
    [FilterKey.policyTier]: FilterKey.policyTier,
    [FilterKey.policyKind]: FilterKey.policyKind,
    [FilterKey.reporter]: FilterKey.reporter,
    [FilterKey.start_time]: FilterKey.start_time,
    [FilterKey.action]: FilterKey.action,
    [FilterKey.staged_action]: FilterKey.staged_action,
    [FilterKey.pending_action]: FilterKey.pending_action,
} as const;

export type OmniFilterParam = keyof typeof OmniFilterKeys;

export const CustomOmniFilterKeys: Pick<
    typeof FilterKey,
    'dest_port' | 'policy' | 'reporter' | 'start_time' | 'action'
> = {
    [FilterKey.dest_port]: FilterKey.dest_port,
    [FilterKey.policy]: FilterKey.policy,
    [FilterKey.reporter]: FilterKey.reporter,
    [FilterKey.start_time]: FilterKey.start_time,
    [FilterKey.action]: FilterKey.action,
} as const;

export type CustomOmniFilterParam = keyof typeof CustomOmniFilterKeys;

const handleEmptyFilters = (filters: any[]) =>
    filters.length ? filters : undefined;

const transformToListFilter = (
    filters: string[] = [],
): FlowsFilterQuery[] | undefined =>
    handleEmptyFilters(
        filters.map((value) => ({
            type: 'Exact',
            value,
        })),
    );

const transformToListFilterSearchRequest = (
    search: string,
): FlowsFilterQuery[] => [
    {
        type: 'Fuzzy',
        value: search,
    },
];

export const transformToFlowsFilterQuery = (
    omniFilterValues: FilterHintValues,
    listFilterId?: DataListOmniFilterParam,
    searchInput?: string,
) => {
    const filterHintsQuery: FlowsFilter = Object.keys(omniFilterValues).reduce(
        (acc, filterKey) => {
            if (
                omniFilterValues[filterKey as FilterHintKey] === undefined ||
                omniFilterValues[filterKey as FilterHintKey].length === 0
            ) {
                return acc;
            }

            const filterId = filterKey as FilterKey;
            const key = OmniFilterProperties[filterId].filterHintsKey;
            return listFilterId === filterId
                ? acc
                : {
                      ...acc,
                      [key]: OmniFilterProperties[
                          filterId
                      ]?.transformToFilterHintRequest(
                          omniFilterValues[filterId as FilterHintKey],
                      ),
                  };
        },
        {},
    );

    if (listFilterId && searchInput) {
        const key = OmniFilterProperties[listFilterId].filterHintsKey;
        filterHintsQuery[key] = OmniFilterProperties[listFilterId]
            .transformToFilterSearchRequest!(searchInput) as FlowsFilterValue;
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
    | 'PolicyName'
    | 'Policy'
    | 'PolicyNamespace'
    | 'PolicyTier'
    | 'PolicyKind'
    | 'Reporter';

export const FilterHintTypes: Record<
    keyof typeof FilterHintKeys,
    FilterHintType
> = {
    [FilterKey.dest_name]: 'DestName',
    [FilterKey.dest_namespace]: 'DestNamespace',
    [FilterKey.source_name]: 'SourceName',
    [FilterKey.source_namespace]: 'SourceNamespace',
    [FilterKey.policy]: 'Policy',
    [FilterKey.policyNamespace]: 'PolicyNamespace',
    [FilterKey.policyTier]: 'PolicyTier',
    [FilterKey.policyKind]: 'PolicyKind',
    [FilterKey.reporter]: 'Reporter',
};

type OmniFilterProperty = {
    selectOptions?: ListOmniFilterOption[];
    defaultOperatorType?: OperatorType;
    label: string;
    limit?: number;
    filterHintsKey: FlowsFilterKeys;
    transformToFilterHintRequest: (
        filters: string[],
    ) => FlowsFilterQuery[] | undefined;
    transformToFilterSearchRequest?: (search: string) =>
        | FlowsFilterQuery[]
        | {
              name: FlowsFilterQuery;
          }[];
    filterComponentProps?: Partial<OmniFilterProps>;
};
export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    OmniFilterProperty
>;

const requestPageSize = 20;

export const OmniFilterProperties: OmniFilterPropertiesType = {
    source_namespace: {
        label: 'Source Namespace',
        limit: requestPageSize,
        filterHintsKey: 'source_namespaces',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
    },
    dest_namespace: {
        label: 'Dest Namespace',
        limit: requestPageSize,
        filterHintsKey: 'dest_namespaces',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
    },
    source_name: {
        label: 'Source',
        limit: requestPageSize,
        filterHintsKey: 'source_names',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
    },
    dest_name: {
        label: 'Destination',
        limit: requestPageSize,
        filterHintsKey: 'dest_names',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
    },
    dest_port: {
        label: 'Port',
        filterHintsKey: 'dest_ports',
        transformToFilterHintRequest: (values: string[]) =>
            handleEmptyFilters(
                values
                    .map(Number)
                    .filter(Boolean)
                    .map((value) => ({ type: 'Exact', value })),
            ),
    },
    protocol: {
        label: 'Protocol',
        filterHintsKey: 'protocols',
        transformToFilterHintRequest: transformToListFilter,
    },
    reporter: {
        label: 'Reporter',
        filterHintsKey: 'reporters',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        filterComponentProps: {
            filters: [
                { label: ReporterLabels.Src, value: 'Src' },
                { label: ReporterLabels.Dst, value: 'Dst' },
            ],
            listType: 'radio',
            showSearch: false,
            onReady: () => undefined,
            width: '100px',
            popoverContentProps: {
                width: '175px',
            },
            formatSelectedLabel: (selectedFilters) => {
                const [selectedFilter] = selectedFilters;

                return selectedFilter
                    ? ReporterLabels[
                          selectedFilter.value as keyof typeof ReporterLabels
                      ]
                    : '';
            },
        },
    },
    policy: {
        label: 'Policy',
        filterHintsKey: 'policies',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyNamespace: {
        label: 'Namespace',
        filterHintsKey: 'policy_namespaces',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyTier: {
        label: 'Tier',
        filterHintsKey: 'policy_tiers',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyKind: {
        label: 'Kind',
        filterHintsKey: 'policy_kinds',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    start_time: {
        label: 'Start Time',
    } as OmniFilterProperty,
    action: {
        label: 'Action',
        filterHintsKey: 'actions',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },

    staged_action: {
        label: 'Staged Action',
        filterHintsKey: 'staged_actions',
        transformToFilterHintRequest: transformToListFilter,
    },

    pending_action: {
        label: 'Pending Action',
        filterHintsKey: 'pending_actions',
        transformToFilterHintRequest: transformToListFilter,
    },
};

export type ListOmniFiltersData = Record<
    DataListOmniFilterParam,
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
    DataListOmniFilterParam,
    ListOmniFilterOption[]
>;

export const transformToQueryPage = (
    { items, total }: ApiFilterResponse,
    page: number,
): QueryPage => ({
    items: items.map(({ value }) => ({ label: value, value })),
    total: total.totalResults,
    currentPage: page,
    nextPage: page + 1,
});
