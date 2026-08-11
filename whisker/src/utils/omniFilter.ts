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

/**
 * This module is the single source of truth for the app's filters. Every
 * filter is one entry in `OmniFilterProperties`; the URL keys, wire keys,
 * autocomplete (filter-hint) requests, and key-set types are all derived from
 * it. To add a standard paged list filter, add one `listFilter(...)` entry —
 * nothing else. To add a bespoke filter, add an entry with `kind: 'custom'`
 * and hand-place its component in OmniFilters.
 */

/**
 * How a filter participates in the app:
 * - 'list':   a paged autocomplete checkbox chip, rendered generically and
 *             fetching its options from flows-filter-hints.
 * - 'static': rendered generically with a fixed option list; never fetches.
 * - 'custom': a URL param owned by a bespoke chip component (some chips own
 *             several params, e.g. the Port chip writes dest_port + protocol).
 * - 'hint':   not a URL param at all; describes an autocomplete source used
 *             inside a custom chip (the policy sub-selects).
 */
type FilterKind = 'list' | 'static' | 'custom' | 'hint';

/** The ?type= values accepted by the flows-filter-hints endpoint. */
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

/** Fields of a PolicyMatch object inside the `policies` wire key. */
type PolicyMatchKey = 'name' | 'namespace' | 'tier' | 'kind';

export type OmniFilterProperty = {
    kind: FilterKind;
    label: string;
    /**
     * The ?type= param sent to flows-filter-hints. Present only on filters
     * whose option values can be autocompleted.
     */
    hintType?: FilterHintType;
    /**
     * The key this filter's value lives under in the `filters` JSON blob sent
     * to the backend. Absent for params that never appear there — start_time
     * reaches the backend as the stream's startTimeGte query param instead.
     * 'hint' entries name the field they search inside `parentFilterKey`.
     */
    filterHintsKey?: FlowsFilterKeys | PolicyMatchKey;
    /** Page size for filter-hint requests. */
    limit?: number;
    /** Selected URL values -> the value stored under filterHintsKey. */
    transformToFilterHintRequest?: (
        filters: any[],
    ) =>
        | FlowsFilterQuery[]
        | Record<string, any>[]
        | string[]
        | string
        | undefined;
    /** Search text -> the fragment injected into a filter-hint request. */
    transformToFilterSearchRequest?: (
        search: string,
    ) =>
        | FlowsFilterQuery[]
        | Record<string, FlowsFilterQuery[]>[]
        | Record<string, string>[];
    /** Extra props for the generic OmniFilter chip (reporter's radio setup). */
    filterComponentProps?: Partial<OmniFilterProps>;
    /** Wire key the search fragment nests under (policy sub-filters). */
    parentFilterKey?: FlowsFilterKeys;
    /** Decodes the single URL value when it is not a plain string list. */
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

export const transformToSinlgeValue = (filters: string[]) => filters[0];

const requestPageSize = 20;

/** The shared shape of a standard paged autocomplete list filter. */
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

/**
 * @deprecated Use the string-literal FilterId union instead; this enum only
 * remains while call sites migrate to registry-derived types.
 */
export enum FilterKey {
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
}

/**
 * Preserves each entry's literal `kind`/`hintType` for the derived types
 * below while exposing every optional OmniFilterProperty field on every
 * entry, and enforces that all FilterKey members are described.
 */
const defineFilters = <T extends Record<FilterKey, OmniFilterProperty>>(
    filters: T,
) => filters as { [K in keyof T]: T[K] & OmniFilterProperty };

/**
 * The filter registry. Non-'hint' entry keys are the URL search params;
 * 'list'/'static' entries render in the filter bar in object order.
 */
export const OmniFilterProperties = defineFilters({
    policy: {
        kind: 'custom',
        label: 'Policy',
        hintType: 'PolicyName',
        filterHintsKey: 'policies',
        limit: requestPageSize,
        transformToFilterHintRequest: transformToPolicyFilterToRequest,
        transformToFilterSearchRequest: transformToListFilterSearchRequest,
        // The policy URL param carries the PolicyFilter[] as a JSON blob.
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
        // reporter never fetches hints; its option list is fixed below.
        hintType: 'Reporter',
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

/** Every filter id in the registry. */
export type FilterId = keyof Registry;

type IdsOfKind<K extends FilterKind> = {
    [P in FilterId]: Registry[P]['kind'] extends K ? P : never;
}[FilterId];

/** Filters rendered as generic paged autocomplete chips. */
export type ListFilterId = IdsOfKind<'list'>;

/** Filters rendered as generic chips with a fixed option list. */
export type StaticFilterId = IdsOfKind<'static'>;

/** Every key that can appear as a URL search param. */
export type UrlFilterKey = Exclude<FilterId, IdsOfKind<'hint'>>;

/** Filters whose option values can be fetched from flows-filter-hints. */
export type FilterHintKey = {
    [P in FilterId]: Registry[P] extends { hintType: FilterHintType }
        ? P
        : never;
}[FilterId];

/** URL params that restart the stream rather than joining the filters blob. */
export type StreamFilterKey = {
    [P in UrlFilterKey]: Registry[P] extends { filterHintsKey: string }
        ? never
        : P;
}[UrlFilterKey];

export const filterIds = Object.keys(OmniFilterProperties) as FilterId[];

const idsOfKind = (kind: FilterKind) =>
    filterIds.filter((id) => OmniFilterProperties[id].kind === kind);

export const listFilterIds = idsOfKind('list') as ListFilterId[];

export const staticFilterIds = idsOfKind('static') as StaticFilterId[];

export const urlFilterKeys = filterIds.filter(
    (id) => OmniFilterProperties[id].kind !== 'hint',
) as UrlFilterKey[];

const filterHintKeyIds = filterIds.filter(
    (id) => OmniFilterProperties[id].hintType !== undefined,
) as FilterHintKey[];

const toKeyRecord = <T extends string>(keys: T[]) =>
    Object.fromEntries(keys.map((key) => [key, key])) as { [P in T]: P };

/** @deprecated Use listFilterIds/staticFilterIds derived from the registry. */
export const ListOmniFilterKeys = toKeyRecord([
    ...listFilterIds,
    ...staticFilterIds,
]);

/** @deprecated Use ListFilterId. */
export type DataListOmniFilterParam = ListFilterId;

/** @deprecated Use FilterHintKey and OmniFilterProperties[id].hintType. */
export const FilterHintKeys = toKeyRecord(filterHintKeyIds);

/** @deprecated Read OmniFilterProperties[id].hintType instead. */
export const FilterHintTypes = Object.fromEntries(
    filterHintKeyIds.map((id) => [id, OmniFilterProperties[id].hintType]),
) as Record<FilterHintKey, FilterHintType>;

/** @deprecated Use StreamFilterKey / the absence of filterHintsKey. */
export const StreamFilterKeys = toKeyRecord(
    urlFilterKeys.filter(
        (id) => OmniFilterProperties[id].filterHintsKey === undefined,
    ) as StreamFilterKey[],
);

/** @deprecated Use filterIds. */
export const OmniFilterKeys = toKeyRecord(filterIds);

/** @deprecated Use FilterId. */
export type OmniFilterParam = FilterId;

/**
 * @deprecated UI-placement list for the filter bar; the custom chips are
 * hand-placed in OmniFilters and this set disappears with them.
 */
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

export type SelectedOmniFilterValues = Partial<
    Record<Exclude<UrlFilterKey, 'policy'>, string[]>
> & {
    policy?: PolicyFilter[];
};

export type SelectedOmniFilterValuesKey = keyof SelectedOmniFilterValues;

/**
 * Folds selected filter values into a FlowsFilter, keyed by each filter's
 * filterHintsKey. Values without a registry entry or without a wire key
 * (start_time) contribute nothing.
 */
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

/** Selected filter values -> the `filters` blob for the flows stream. */
export const toFlowsFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
): string => toQueryString(toFlowsFilter(omniFilterValues));

/**
 * Builds the `filters` blob for a flows-filter-hints request: the other
 * active filters as narrowing context — the filter being populated is
 * excluded so users can widen their selection — plus the search term,
 * nested under parentFilterKey for the policy sub-filters.
 */
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

/** @deprecated Use toFlowsFilterQuery / toHintFilterQuery. */
export const transformToFlowsFilterQuery = (
    omniFilterValues: SelectedOmniFilterValues,
    listFilterId?: FilterHintKey,
    searchInput?: string,
) =>
    listFilterId
        ? toHintFilterQuery(omniFilterValues, listFilterId, searchInput)
        : toFlowsFilterQuery(omniFilterValues);

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
