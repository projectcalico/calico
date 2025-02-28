import {
    OmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { ApiFilterResponse, QueryPage } from '@/types/api';

export enum OmniFilterParam {
    policy = 'policy',
    namespace = 'namespace',
    source_namespace = 'source_namespace',
    dest_namespace = 'dest_namespace',
}

export type OmniFilterPropertiesType = Record<
    OmniFilterParam,
    {
        selectOptions?: OmniFilterOption[];
        defaultOperatorType?: OperatorType;
        label: string;
    }
>;

export const OmniFilterProperties: OmniFilterPropertiesType = {
    policy: {
        label: 'Policy',
    },
    namespace: {
        label: 'Namespace',
    },
    source_namespace: {
        label: 'Source',
    },
    dest_namespace: {
        label: 'Destination',
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
