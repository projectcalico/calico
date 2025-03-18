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
    start_time: Date;
    end_time: Date;
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
    total: number;
};

export type UseStreamResult<T> = {
    data: T[];
    error: ApiError | null;
    startStream: (path?: string) => void;
    stopStream: () => void;
    isWaiting: boolean;
    isDataStreaming: boolean;
    hasStoppedStreaming: boolean;
};

export type FilterHintQuery = {
    value: string | number;
    type: 'Exact' | 'Fuzzy';
};

export type FilterHintsRequest = Partial<{
    policies: FilterHintQuery[];
    source_names: FilterHintQuery[];
    dest_names: FilterHintQuery[];
    source_namespaces: FilterHintQuery[];
    dest_namespaces: FilterHintQuery[];
    protocols: FilterHintQuery[];
    dest_ports: FilterHintQuery[];
    actions: ('Allow' | 'Deny' | 'Pass')[];
}>;

export type FilterHintQueriesKeys = keyof Omit<FilterHintsRequest, 'actions'>;

export type FilterHintsListKeys = keyof Omit<
    FilterHintsRequest,
    'actions' | 'dest_ports' | 'protocols'
>;
