import { OmniFilterOption as ListOmniFilterOption } from '@/libs/tigera/ui-components/components/common/OmniFilter/types';
import { ListOmniFilterParam, OmniFilterParam } from '@/utils/omniFilter';
import { FlowLogAction } from './render';

type Policy = {
    kind: string;
    name: string;
    namespace: string;
    tier: string;
    action: string;
    policy_index: number;
    rule_index: number;
    trigger: null;
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
    policies: {
        enforced: Policy[];
        pending: Policy[];
    };
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
    filterParam: ListOmniFilterParam;
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
    policies: { name: FlowsFilterQuery }[];
    source_names: FlowsFilterQuery[];
    dest_names: FlowsFilterQuery[];
    source_namespaces: FlowsFilterQuery[];
    dest_namespaces: FlowsFilterQuery[];
    protocols: FlowsFilterQuery[];
    dest_ports: FlowsFilterQuery[];
    actions: ('Allow' | 'Deny' | 'Pass')[];
}>;

export type FlowsFilterKeys = keyof FlowsFilter;

export type BannerContent = {
    bannerText: string;
    bannerLink: string;
};
