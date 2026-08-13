import {
    ApiFilterResponse,
    FlowsFilter,
    FlowsFilterQuery,
    QueryPage,
} from '@/types/api';
import { OmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';

export type FilterHintType =
    | 'DestName'
    | 'SourceName'
    | 'DestNamespace'
    | 'SourceNamespace'
    | 'PolicyTier'
    | 'PolicyName'
    | 'PolicyKind'
    | 'PolicyNamespace';

type DataFilter = {
    hintType: FilterHintType;
    pageSize: number;
    toSearch: (search: string) => FlowsFilter;
};

const requestPageSize = 20;

const fuzzy = (value: string): FlowsFilterQuery => ({ type: 'Fuzzy', value });

export const dataFilters = {
    source_namespace: {
        hintType: 'SourceNamespace',
        pageSize: requestPageSize,
        toSearch: (search) => ({ source_namespaces: [fuzzy(search)] }),
    },
    source_name: {
        hintType: 'SourceName',
        pageSize: requestPageSize,
        toSearch: (search) => ({ source_names: [fuzzy(search)] }),
    },
    dest_namespace: {
        hintType: 'DestNamespace',
        pageSize: requestPageSize,
        toSearch: (search) => ({ dest_namespaces: [fuzzy(search)] }),
    },
    dest_name: {
        hintType: 'DestName',
        pageSize: requestPageSize,
        toSearch: (search) => ({ dest_names: [fuzzy(search)] }),
    },
    policyName: {
        hintType: 'PolicyName',
        pageSize: requestPageSize,
        toSearch: (search) => ({ policies: [{ name: fuzzy(search) }] }),
    },
    policyNamespace: {
        hintType: 'PolicyNamespace',
        pageSize: requestPageSize,
        toSearch: (search) => ({ policies: [{ namespace: fuzzy(search) }] }),
    },
    policyTier: {
        hintType: 'PolicyTier',
        pageSize: requestPageSize,
        toSearch: (search) => ({ policies: [{ tier: fuzzy(search) }] }),
    },
    policyKind: {
        hintType: 'PolicyKind',
        pageSize: requestPageSize,
        toSearch: (search) => ({ policies: [{ kind: search }] }),
    },
} satisfies Record<string, DataFilter>;

export type DataFilterId = keyof typeof dataFilters;

export type ListOmniFilterData = {
    filters: OmniFilterOption[] | null;
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
