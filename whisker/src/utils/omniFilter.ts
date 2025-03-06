import {
    OmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { ApiFilterQuery, ApiFilterResponse, QueryPage } from '@/types/api';

export enum OmniFilterParam {
    policy = 'policy',
    source_name = 'source_name',
    source_namespace = 'source_namespace',
    dest_name = 'dest_name',
    dest_namespace = 'dest_namespace',
}

export const transformApiFilterQuery = (
    input: string | undefined,
    filters: SelectedOmniFilters,
): ApiFilterQuery => ({
    input,
    filters:
        Object.keys(filters).length >= 1 ? JSON.stringify(filters) : undefined,
});

export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    {
        selectOptions?: OmniFilterOption[];
        defaultOperatorType?: OperatorType;
        label: string;
        limit: number;
    }
>;

const requestPageSize = 20;

export const OmniFilterProperties: OmniFilterPropertiesType = {
    policy: {
        label: 'Policy',
        limit: requestPageSize,
    },
    source_namespace: {
        label: 'Source Namespace',
        limit: requestPageSize,
    },
    dest_namespace: {
        label: 'Destination Namespace',
        limit: requestPageSize,
    },
    source_name: {
        label: 'Source',
        limit: requestPageSize,
    },
    dest_name: {
        label: 'Destination',
        limit: requestPageSize,
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
