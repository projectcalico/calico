import {
    OmniFilterOption,
    OperatorType,
} from '@/libs/tigera/ui-components/components/common/OmniFilter/types';

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
        selectOptions: [
            { label: 'Policy-1', value: 'p-1' },
            { label: 'Policy-2', value: 'p-2' },
            { label: 'Policy-3', value: 'p-3' },
        ],
    },
    namespace: {
        label: 'Namespace',
        selectOptions: [
            { label: 'Namespace-1', value: 'p-1' },
            { label: 'Namespace-2', value: 'p-2' },
            { label: 'Namespace-3', value: 'p-3' },
        ],
    },
    source_namespace: {
        label: 'Source',
        selectOptions: [
            { label: 'Source-1', value: 'p-1' },
            { label: 'Source-2', value: 'p-2' },
            { label: 'Source-3', value: 'p-3' },
        ],
    },
    dest_namespace: {
        label: 'Destination',
        selectOptions: [
            { label: 'Destination-1', value: 'p-1' },
            { label: 'Destination-2', value: 'p-2' },
            { label: 'Destination-3', value: 'p-3' },
        ],
    },
};

export type OmniFilterData = Record<
    OmniFilterParam,
    {
        filters: OmniFilterOption[] | null;
        isLoading: boolean;
        total?: number;
    }
>;

export type SelectedOmniFilterData = Partial<OmniFilterData>;

export type SelectedOmniFilters = Partial<Record<OmniFilterParam, string[]>>;

export type SelectedOmniFilterOptions = Record<
    OmniFilterParam,
    OmniFilterOption[]
>;
