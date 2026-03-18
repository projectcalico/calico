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
import { PolicyFilter } from '@/features/flowLogs/components/PolicyOmniFilter';

export enum FilterKey {
    // policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
    protocol = 'protocol',
    dest_port = 'dest_port',
    policy = 'policy',
    policyName = 'policyName',
    policyNamespace = 'policyNamespace',
    policyTier = 'policyTier',
    policyKind = 'policyKind',
    reporter = 'reporter',
    start_time = 'start_time',
    action = 'action',
    staged_action = 'staged_action',
    pending_action = 'pending_action',
}

export const ListOmniFilterKeys: Omit<
    typeof FilterKey,
    | 'protocol'
    | 'dest_port'
    | 'policy'
    | 'policyNamespace'
    | 'policyTier'
    | 'policyKind'
    | 'policyName'
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
    [FilterKey.policyName]: FilterKey.policyName,
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
    [FilterKey.policyName]: FilterKey.policyName,
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

const transformToExactFilter = (value: string) => ({
    type: 'Exact',
    value,
});

const transformToListFilter = (
    filters: string[] = [],
): FlowsFilterQuery[] | undefined =>
    handleEmptyFilters(filters.map(transformToExactFilter));

const transformToFuzzyFilter = (value: string): FlowsFilterQuery => ({
    type: 'Fuzzy',
    value,
});

const transformToListFilterSearchRequest = (
    search: string,
): FlowsFilterQuery[] => [transformToFuzzyFilter(search)];

export const transformToPolicyFilterToRequest = (values: PolicyFilter[]) =>
    values.map((value) => {
        const filter: Record<string, any> = {};

        if (value.name) {
            filter.name = transformToExactFilter(value.name);
        }

        if (value.namespace) {
            filter.namespace = transformToExactFilter(value.namespace);
        }

        if (value.tier) {
            filter.tier = transformToExactFilter(value.tier);
        }

        if (value.kind) {
            filter.kind = value.kind;
        }

        return filter;
    });

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
                      ]?.transformToFilterHintRequest?.(
                          omniFilterValues[filterId as FilterHintKey],
                      ),
                  };
        },
        {},
    );

    const parentFilterKey = listFilterId
        ? OmniFilterProperties[listFilterId].parentFilterKey
        : undefined;

    if (listFilterId && searchInput) {
        const key =
            parentFilterKey ??
            OmniFilterProperties[listFilterId].filterHintsKey;
        const filterValue = OmniFilterProperties[listFilterId]
            .transformToFilterSearchRequest!(searchInput) as FlowsFilterValue;
        filterHintsQuery[key as FlowsFilterKeys] = filterValue;
    }

    return Object.keys(filterHintsQuery).length
        ? JSON.stringify(filterHintsQuery)
        : '';
};

export const transformToList = (filters: string[]) => [filters[0]];

export const transformToSinlgeValue = (filters: string[]) => filters[0];

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
    [FilterKey.policy]: 'PolicyName',
    [FilterKey.policyNamespace]: 'PolicyNamespace',
    [FilterKey.policyTier]: 'PolicyTier',
    [FilterKey.policyKind]: 'PolicyKind',
    [FilterKey.policyName]: 'PolicyName',
    [FilterKey.reporter]: 'Reporter',
};

type OmniFilterProperty = {
    selectOptions?: ListOmniFilterOption[];
    defaultOperatorType?: OperatorType;
    label: string;
    limit?: number;
    filterHintsKey: string;
    transformToFilterHintRequest?: (
        filters: any[],
    ) =>
        | FlowsFilterQuery[]
        | Record<string, any>[]
        | string[]
        | string
        | undefined;
    transformToFilterSearchRequest?: (
        search: string,
    ) =>
        | FlowsFilterQuery[]
        | Record<string, FlowsFilterQuery[]>[]
        | Record<string, string>[];
    filterComponentProps?: Partial<OmniFilterProps>;
    parentFilterKey?: FlowsFilterKeys;
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
        filterHintsKey: 'reporter',
        transformToFilterHintRequest: transformToSinlgeValue,
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
        transformToFilterHintRequest: transformToPolicyFilterToRequest,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        limit: requestPageSize,
    },
    policyNamespace: {
        label: 'Namespace',
        filterHintsKey: 'namespace',
        parentFilterKey: 'policies',
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    namespace: transformToFuzzyFilter(value),
                },
            ] as any;
        },
        limit: requestPageSize,
    },
    policyTier: {
        label: 'Tier',
        filterHintsKey: 'tier',
        parentFilterKey: 'policies',
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    tier: transformToFuzzyFilter(value),
                },
            ] as any;
        },
        limit: requestPageSize,
    },
    policyKind: {
        label: 'Kind',
        filterHintsKey: 'kind',
        parentFilterKey: 'policies',
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    kind: value,
                },
            ];
        },
        limit: requestPageSize,
    },
    policyName: {
        label: 'Name',
        filterHintsKey: 'name',
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    name: transformToFuzzyFilter(value),
                },
            ] as any;
        },
        limit: requestPageSize,
        parentFilterKey: 'policies',
    },
    start_time: {
        label: 'Start Time',
    } as OmniFilterProperty,
    action: {
        label: 'Action',
        filterHintsKey: 'actions',
        transformToFilterHintRequest: transformToList,
        limit: requestPageSize,
    },

    staged_action: {
        label: 'Staged Action',
        filterHintsKey: 'staged_actions',
        transformToFilterHintRequest: transformToList,
    },

    pending_action: {
        label: 'Pending Action',
        filterHintsKey: 'pending_actions',
        transformToFilterHintRequest: transformToList,
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
