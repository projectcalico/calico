import { OmniFilterProps } from '@/libs/tigera/ui-components/components/common/OmniFilter';
import { OmniFilterOption as ListOmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import {
    ApiFilterResponse,
    FlowsFilterKeys,
    FlowsFilter,
    FlowsFilterQuery,
    QueryPage,
    FlowsFilterValue,
} from '@/types/api';
import { ReporterLabels } from '@/types/render';
import { PolicyFilter } from '@/features/flowLogs/components/PolicyOmniFilter';

type FilterKind = 'list' | 'static' | 'custom' | 'hint';

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

type PolicyMatchKey = 'name' | 'namespace' | 'tier' | 'kind';

export type OmniFilterProperty = {
    kind: FilterKind;
    label: string;
    hintType?: FilterHintType;
    filterHintsKey?: FlowsFilterKeys | PolicyMatchKey;
    limit?: number;
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
    parseUrlValue?: (value: string) => unknown;
};

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

export const transformToList = (filters: string[]) => [filters[0]];

export const transformToSingleValue = (filters: string[]) => filters[0];

const requestPageSize = 20;

const listFilter = (
    label: string,
    hintType: FilterHintType,
    filterHintsKey: FlowsFilterKeys,
) =>
    ({
        kind: 'list',
        label,
        hintType,
        filterHintsKey,
        limit: requestPageSize,
        transformToFilterHintRequest: transformToListFilter,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
    }) as const;

const defineFilters = <T extends Record<string, OmniFilterProperty>>(
    filters: T,
) => filters as { [K in keyof T]: T[K] & OmniFilterProperty };

export const OmniFilterProperties = defineFilters({
    policy: {
        kind: 'custom',
        label: 'Policy',
        hintType: 'PolicyName',
        filterHintsKey: 'policies',
        limit: requestPageSize,
        transformToFilterHintRequest: transformToPolicyFilterToRequest,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        parseUrlValue: (value: string) => {
            try {
                return JSON.parse(value);
            } catch {
                return [];
            }
        },
    },
    source_namespace: listFilter(
        'Source Namespace',
        'SourceNamespace',
        'source_namespaces',
    ),
    source_name: listFilter('Source', 'SourceName', 'source_names'),
    dest_namespace: listFilter(
        'Dest Namespace',
        'DestNamespace',
        'dest_namespaces',
    ),
    dest_name: listFilter('Destination', 'DestName', 'dest_names'),
    reporter: {
        kind: 'static',
        label: 'Reporter',
        hintType: 'Reporter',
        filterHintsKey: 'reporter',
        transformToFilterHintRequest: transformToSingleValue,
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
    dest_port: {
        kind: 'custom',
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
        kind: 'custom',
        label: 'Protocol',
        filterHintsKey: 'protocols',
        transformToFilterHintRequest: transformToListFilter,
    },
    action: {
        kind: 'custom',
        label: 'Action',
        filterHintsKey: 'actions',
        limit: requestPageSize,
        transformToFilterHintRequest: transformToList,
    },
    staged_action: {
        kind: 'custom',
        label: 'Staged Action',
        filterHintsKey: 'pending_actions',
        transformToFilterHintRequest: transformToList,
    },
    start_time: {
        kind: 'custom',
        label: 'Start Time',
    },
    policyName: {
        kind: 'hint',
        label: 'Name',
        hintType: 'PolicyName',
        filterHintsKey: 'name',
        parentFilterKey: 'policies',
        limit: requestPageSize,
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    name: transformToFuzzyFilter(value),
                },
            ] as any;
        },
    },
    policyNamespace: {
        kind: 'hint',
        label: 'Namespace',
        hintType: 'PolicyNamespace',
        filterHintsKey: 'namespace',
        parentFilterKey: 'policies',
        limit: requestPageSize,
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    namespace: transformToFuzzyFilter(value),
                },
            ] as any;
        },
    },
    policyTier: {
        kind: 'hint',
        label: 'Tier',
        hintType: 'PolicyTier',
        filterHintsKey: 'tier',
        parentFilterKey: 'policies',
        limit: requestPageSize,
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    tier: transformToFuzzyFilter(value),
                },
            ] as any;
        },
    },
    policyKind: {
        kind: 'hint',
        label: 'Kind',
        hintType: 'PolicyKind',
        filterHintsKey: 'kind',
        parentFilterKey: 'policies',
        limit: requestPageSize,
        transformToFilterSearchRequest: (value) => {
            return [
                {
                    kind: value,
                },
            ];
        },
    },
});

type Registry = typeof OmniFilterProperties;

export type FilterId = keyof Registry;

type IdsOfKind<K extends FilterKind> = {
    [P in FilterId]: Registry[P]['kind'] extends K ? P : never;
}[FilterId];

export type ListFilterId = IdsOfKind<'list'>;

export type StaticFilterId = IdsOfKind<'static'>;

export type UrlFilterKey = Exclude<FilterId, IdsOfKind<'hint'>>;

export type CustomFilterId = IdsOfKind<'custom'>;

export type FilterHintKey = {
    [P in FilterId]: Registry[P] extends { hintType: FilterHintType }
        ? P
        : never;
}[FilterId];

export const filterIds = Object.keys(OmniFilterProperties) as FilterId[];

const idsOfKind = (kind: FilterKind) =>
    filterIds.filter((id) => OmniFilterProperties[id].kind === kind);

export const listFilterIds = idsOfKind('list') as ListFilterId[];

export const staticFilterIds = idsOfKind('static') as StaticFilterId[];

export const customFilterIds = idsOfKind('custom') as CustomFilterId[];

export const urlFilterKeys = filterIds.filter(
    (id) => OmniFilterProperties[id].kind !== 'hint',
) as UrlFilterKey[];

export type SelectedOmniFilterValues = Partial<
    Record<Exclude<UrlFilterKey, 'policy'>, string[]>
> & {
    policy?: PolicyFilter[];
};

type SelectedOmniFilterValuesKey = keyof SelectedOmniFilterValues;

const toFlowsFilter = (
    omniFilterValues: SelectedOmniFilterValues,
    excludeFilterId?: FilterId,
): FlowsFilter =>
    Object.keys(omniFilterValues).reduce((acc, filterKey) => {
        const filterId = filterKey as SelectedOmniFilterValuesKey;
        const property: OmniFilterProperty | undefined =
            OmniFilterProperties[filterId];
        const values = omniFilterValues[filterId];

        if (
            !property?.filterHintsKey ||
            filterId === excludeFilterId ||
            values === undefined ||
            values.length === 0
        ) {
            return acc;
        }

        return {
            ...acc,
            [property.filterHintsKey]:
                property.transformToFilterHintRequest?.(values),
        };
    }, {});

const toQueryString = (filters: FlowsFilter) =>
    Object.keys(filters).length ? JSON.stringify(filters) : '';

export const toFlowsFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
): string => toQueryString(toFlowsFilter(omniFilterValues));

export const toHintFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
    filterId: FilterHintKey,
    searchInput?: string,
): string => {
    const filterHintsQuery = toFlowsFilter(omniFilterValues, filterId);
    const { parentFilterKey, filterHintsKey, transformToFilterSearchRequest } =
        OmniFilterProperties[filterId];

    if (searchInput) {
        const key = parentFilterKey ?? filterHintsKey;
        filterHintsQuery[key as FlowsFilterKeys] =
            transformToFilterSearchRequest!(searchInput) as FlowsFilterValue;
    }

    return toQueryString(filterHintsQuery);
};

export type ListOmniFilterData = {
    filters: ListOmniFilterOption[] | null;
    isLoading: boolean;
    total?: number;
};

export const transformToQueryPage = (
    { items, total }: ApiFilterResponse,
    page: number,
): QueryPage => ({
    items: items.map(({ value }) => ({ label: value, value })),
    total: total.totalResults,
    currentPage: page,
    nextPage: page + 1,
});
