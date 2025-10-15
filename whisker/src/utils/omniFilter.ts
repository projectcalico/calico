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
import { FilterHintValues } from '@/types/render';

export enum FilterKey {
    policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
    protocol = 'protocol',
    dest_port = 'dest_port',
    policyV2 = 'policyV2',
    policyV2Namespace = 'policyV2Namespace',
    policyV2Tier = 'policyV2Tier',
    policyV2Kind = 'policyV2Kind',
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
    | 'policyV2'
    | 'policyV2Namespace'
    | 'policyV2Tier'
    | 'policyV2Kind'
    | 'start_time'
    | 'action'
    | 'staged_action'
    | 'pending_action'
> = {
    [FilterKey.policy]: FilterKey.policy,
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
    [FilterKey.policy]: FilterKey.policy,
    [FilterKey.source_namespace]: FilterKey.source_namespace,
    [FilterKey.source_name]: FilterKey.source_name,
    [FilterKey.dest_namespace]: FilterKey.dest_namespace,
    [FilterKey.dest_name]: FilterKey.dest_name,
    [FilterKey.policyV2Tier]: FilterKey.policyV2Tier,
    [FilterKey.policyV2Namespace]: FilterKey.policyV2Namespace,
    [FilterKey.policyV2Kind]: FilterKey.policyV2Kind,
    [FilterKey.policyV2]: FilterKey.policyV2,
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
    [FilterKey.policyV2]: FilterKey.policyV2,
    [FilterKey.policyV2Namespace]: FilterKey.policyV2Namespace,
    [FilterKey.policyV2Tier]: FilterKey.policyV2Tier,
    [FilterKey.policyV2Kind]: FilterKey.policyV2Kind,
    [FilterKey.reporter]: FilterKey.reporter,
    [FilterKey.start_time]: FilterKey.start_time,
    [FilterKey.action]: FilterKey.action,
    [FilterKey.staged_action]: FilterKey.staged_action,
    [FilterKey.pending_action]: FilterKey.pending_action,
} as const;

export type OmniFilterParam = keyof typeof OmniFilterKeys;

export const CustomOmniFilterKeys: Pick<
    typeof FilterKey,
    'dest_port' | 'policyV2' | 'reporter' | 'start_time' | 'action'
> = {
    [FilterKey.dest_port]: FilterKey.dest_port,
    [FilterKey.policyV2]: FilterKey.policyV2,
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
                      ].transformToFilterHintRequest(
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
    | 'PolicyV2'
    | 'PolicyV2Namespace'
    | 'PolicyV2Tier'
    | 'PolicyV2Kind'
    | 'Reporter';

export const FilterHintTypes: Record<
    keyof typeof FilterHintKeys,
    FilterHintType
> = {
    [FilterKey.dest_name]: 'DestName',
    [FilterKey.dest_namespace]: 'DestNamespace',
    [FilterKey.source_name]: 'SourceName',
    [FilterKey.source_namespace]: 'SourceNamespace',
    [FilterKey.policy]: 'PolicyName',
    [FilterKey.policyV2]: 'PolicyV2',
    [FilterKey.policyV2Namespace]: 'PolicyV2Namespace',
    [FilterKey.policyV2Tier]: 'PolicyV2Tier',
    [FilterKey.policyV2Kind]: 'PolicyV2Kind',
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
    policy: {
        label: 'Policy',
        limit: requestPageSize,
        filterHintsKey: 'policies',
        transformToFilterHintRequest: (values: string[]) =>
            handleEmptyFilters(
                values.map((value) => ({
                    name: { type: 'Exact', value },
                })),
            ),
        transformToFilterSearchRequest: (search) => [
            {
                name: {
                    type: 'Fuzzy',
                    value: search,
                },
            },
        ],
    },
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
                { label: 'src', value: 'src' },
                { label: 'dst', value: 'dst' },
            ],
            listType: 'radio',
            showSearch: false,
            onReady: () => undefined,
            width: '100px',
            popoverContentProps: {
                width: '175px',
            },
        },
    },
    policyV2: {
        label: 'Policy V2',
        filterHintsKey: 'policiesV2',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyV2Namespace: {
        label: 'Namespace',
        filterHintsKey: 'policiesV2Namespaces',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyV2Tier: {
        label: 'Tier',
        filterHintsKey: 'policyV2Tiers',
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyV2Kind: {
        label: 'Kind',
        filterHintsKey: 'policyV2Kinds',
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
