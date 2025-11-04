import { OmniFilterOption as ListOmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { DataListOmniFilterParam, OmniFilterParam } from '@/utils/omniFilter';
import { FlowLogAction } from './render';

export type Policy = {
    kind: string;
    name: string;
    namespace: string;
    tier: string;
    action: string;
    policy_index: number | null;
    rule_index: number | null;
    trigger?: Policy | null;
};

export type PoliciesLogEntries = {
    [key: string]: Policy[];
};

export type FlowLog = {
    start_time: string;
    end_time: string;
    action: FlowLogAction;
    source_name: string;
    source_namespace: string;
    source_labels: string;
    dest_name: string;
    dest_namespace: string;
    dest_labels: string;
    protocol: string;
    dest_port: string;
    reporter: string;
    packets_in: string;
    packets_out: string;
    bytes_in: string;
    bytes_out: string;
    policies: PoliciesLogEntries;
};

export type ApiError = {
    data?: any;
    response?: Response;
};

export type QueryPage = {
    items: ListOmniFilterOption[];
    total: number;
    currentPage?: number;
    nextPage?: number;
};

export type OmniFilterDataQuery = {
    searchOption?: string;
    filterParam: DataListOmniFilterParam;
};

export type OmniFilterDataQueries = Record<
    OmniFilterParam,
    OmniFilterDataQuery | null
>;

export type FilterHint = {
    value: string;
};

export type ApiFilterResponse = {
    items: FilterHint[];
    total: {
        totalResults: number;
        totalPages: number;
    };
};

export type StartStreamOptions = {
    path?: string;
    isUpdate?: boolean;
};

export type UseStreamResult<T> = {
    data: T[];
    error: ApiError | null;
    startStream: (options?: StartStreamOptions) => void;
    stopStream: () => void;
    isWaiting: boolean;
    isDataStreaming: boolean;
    hasStoppedStreaming: boolean;
    isFetching: boolean;
    totalItems: number;
};

export type UseStreamOptions<S, R> = {
    path: string;
    transformResponse: (stream: S) => R | null;
};

export type FlowsFilterQuery = {
    value: string | number;
    type: 'Exact' | 'Fuzzy';
};

export type FlowsFilterValue =
    | (FlowsFilterQuery[] & { name: FlowsFilterQuery }[])
    | undefined;

export type FlowsFilter = Partial<{
    source_names: FlowsFilterQuery[];
    dest_names: FlowsFilterQuery[];
    source_namespaces: FlowsFilterQuery[];
    dest_namespaces: FlowsFilterQuery[];
    protocols: FlowsFilterQuery[];
    dest_ports: FlowsFilterQuery[];
    policies: FlowsFilterQuery[];
    policy_namespaces: FlowsFilterQuery[];
    policy_tiers: FlowsFilterQuery[];
    policy_kinds: FlowsFilterQuery[];
    reporters: FlowsFilterQuery[];
    actions: FlowsFilterQuery[];
    staged_actions: FlowsFilterQuery[];
    pending_actions: FlowsFilterQuery[];
}>;

export type FlowsFilterKeys = keyof FlowsFilter;

export type BannerContent = {
    bannerText: string;
    bannerLink: string;
};
